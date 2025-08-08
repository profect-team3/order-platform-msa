package app.apigateway;

import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {
	@Bean
	public GroupedOpenApi authApi() {
		return GroupedOpenApi.builder()
			.group("auth")
			.pathsToMatch("/auth/**")
			.build();
	}

	@Bean
	public GroupedOpenApi userApi() {
		return GroupedOpenApi.builder()
			.group("user")
			.pathsToMatch("/user/**")
			.build();
	}
}
