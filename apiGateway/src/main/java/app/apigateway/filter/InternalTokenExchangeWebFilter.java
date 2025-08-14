package app.apigateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.http.*;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
@RequiredArgsConstructor
public class InternalTokenExchangeWebFilter implements WebFilter, Ordered {

	private final WebClient.Builder httpBuilder;

	@Value("${auth.internal-token.url}") private String tokenUrl;

	private static final Set<String> SKIP_PREFIXES = Set.of(
		"/auth", "/oauth", "/oauth2", "/actuator", "/docs", "/swagger-ui", "/v3/api-docs"
	);

	private static final class Entry {
		final String token; final long expEpochSec;
		Entry(String t, long e){ this.token=t; this.expEpochSec=e; }
	}
	private final Map<String, Entry> userTokenCache = new ConcurrentHashMap<>();

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		final String path   = exchange.getRequest().getURI().getPath();
		final HttpMethod method = exchange.getRequest().getMethod();
		final String reqId  = Optional.ofNullable(exchange.getRequest().getId()).orElse("no-req-id");

		if (log.isDebugEnabled()) log.debug("[GW][{}] IN {} {}", reqId, method, path);

		if (method == HttpMethod.OPTIONS || shouldSkip(path)) {
			if (log.isDebugEnabled()) log.debug("[GW][{}] SKIP path={}", reqId, path);
			return chain.filter(exchange);
		}

		return exchange.getPrincipal()
			.ofType(JwtAuthenticationToken.class)
			.flatMap(auth -> {
				final String userId = auth.getToken().getSubject();
				final String userRole =auth.getToken().getClaim("user_role");
				if (userId == null || userId.isBlank()) {
					log.debug("[GW][{}] external JWT exists but sub(userId) is blank → pass-through", reqId);
					return chain.filter(exchange);
				}
				if (log.isDebugEnabled()) log.debug("[GW][{}] external JWT sub(userId)={}", reqId, userId);

				return getOrExchangeInternalTokenForUser(userId,userRole, reqId)
					.flatMap(internal -> {
						if (log.isDebugEnabled()) {
							log.debug("[GW][{}] got INTERNAL token (len={}, prefix={})",
								reqId, internal.length(),
								internal.substring(0, Math.min(10, internal.length())) + "...");
						}
						var mutatedReq = exchange.getRequest().mutate()
							.headers(h -> {
								h.set(HttpHeaders.AUTHORIZATION, "Bearer " + internal);
								h.set("X-User-Id", userId);
								h.set("X-Caller-Service", "svc-gateway");
							})
							.build();
						return chain.filter(exchange.mutate().request(mutatedReq).build());
					})
					.onErrorResume(e -> {
						log.warn("[GW][{}] token exchange FAILED: {}", reqId, e.toString());
						return chain.filter(exchange);
					});
			})
			.switchIfEmpty(chain.filter(exchange));
	}

	private boolean shouldSkip(String p) {
		if (p == null) return false;
		for (String s : SKIP_PREFIXES) if (p.startsWith(s)) return true;
		return false;
	}

	private Mono<String> getOrExchangeInternalTokenForUser(String userId, String userRole,String reqId) {
		long now = Instant.now().getEpochSecond();
		Entry e = userTokenCache.get(userId);
		if (e != null && now < e.expEpochSec - 5) {
			if (log.isDebugEnabled())
				log.debug("[GW][{}] HIT cache for userId={} (expIn {}s)", reqId, userId, (e.expEpochSec - now));
			return Mono.just(e.token);
		}
		if (log.isDebugEnabled())
			log.debug("[GW][{}] MISS cache → requesting internal token for userId={}", reqId, userId);

		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("grant_type", "client_credentials");
		form.add("user_id", userId);
		form.add("user_role", userRole);

		WebClient http = httpBuilder.build();

		return http.post()
			.uri(tokenUrl)
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.accept(MediaType.APPLICATION_JSON)
			.body(BodyInserters.fromFormData(form))
			.exchangeToMono(resp -> {
				if (!resp.statusCode().is2xxSuccessful()) {
					return resp.bodyToMono(String.class).defaultIfEmpty("")
						.flatMap(body -> Mono.error(new IllegalStateException(
							"token issue failed " + resp.statusCode() + " body=" + safeSnippet(body))));
				}
				return resp.bodyToMono(Map.class);
			})
			.map(res -> {
				Object tok = res.get("access_token");
				Object exp = res.getOrDefault("expires_in", 60);
				if (tok == null) {
					log.warn("[GW][{}] token response missing access_token: {}", reqId, res);
					throw new IllegalStateException("no access_token in response");
				}
				long expIn = (exp instanceof Number n) ? n.longValue() : Long.parseLong(String.valueOf(exp));
				long expEpochSec = Instant.now().getEpochSecond() + expIn;
				String token = tok.toString();
				userTokenCache.put(userId, new Entry(token, expEpochSec));
				if (log.isDebugEnabled())
					log.debug("[GW][{}] cache SET for userId={} (ttl {}s)", reqId, userId, expIn);
				return token;
			});
	}

	private String safeSnippet(String s) {
		if (s == null) return "";
		return s.length() > 300 ? s.substring(0, 300) + "..." : s;
	}

	@Override
	public int getOrder() {
		return SecurityWebFiltersOrder.AUTHENTICATION.getOrder() + 1;
	}
}