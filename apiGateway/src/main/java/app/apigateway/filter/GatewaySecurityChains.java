package app.apigateway.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.*;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Configuration
@EnableWebFluxSecurity
@EnableMethodSecurity
public class GatewaySecurityChains {

	@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
	private String jwkSetUri;

	@Bean
	SecurityWebFilterChain securityFilterChain(
		ServerHttpSecurity http,
		ReactiveJwtDecoder jwtDecoder,
		Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> converter
	) {
		return http
			.csrf(ServerHttpSecurity.CsrfSpec::disable)
			.authorizeExchange(ex -> ex
				.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
				.pathMatchers("/auth/**",
					"/actuator/health",
					"/docs","/oauth/jwks",
					"/swagger-ui/**",
					"/v3/api-docs/**","/user/user/signup","/payment/checkout").permitAll()
				.anyExchange().authenticated()
			)
			.oauth2ResourceServer(o -> o.jwt(j -> j
				.jwtDecoder(jwtDecoder)
				.jwtAuthenticationConverter(converter)
			))
			.build();
	}
	@Bean
	ReactiveJwtDecoder reactiveJwtDecoder() {
		var dec = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
		OAuth2TokenValidator<Jwt> ts  = new JwtTimestampValidator(Duration.ofSeconds(60));
		dec.setJwtValidator(new DelegatingOAuth2TokenValidator<>( ts));
		return dec;
	}
	@Bean
	Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> reactiveConverter() {
		var gac = new JwtGrantedAuthoritiesConverter();
		gac.setAuthoritiesClaimName("roles");
		gac.setAuthorityPrefix("ROLE_");
		var delegate = new JwtAuthenticationConverter();
		delegate.setJwtGrantedAuthoritiesConverter(gac);
		return new ReactiveJwtAuthenticationConverterAdapter(delegate);
	}
}

