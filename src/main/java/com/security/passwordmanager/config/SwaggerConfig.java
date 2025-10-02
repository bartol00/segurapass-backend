package com.security.passwordmanager.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.annotation.AuthenticationPrincipal;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .components(new Components().addSecuritySchemes("bearerAuth",
                        new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                ))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
    }

    @Bean
    public OperationCustomizer customizeOperation() {
        return (Operation operation, org.springframework.web.method.HandlerMethod handlerMethod) -> {

            if (operation.getParameters() != null) {
                operation.getParameters().removeIf(p -> {
                    for (java.lang.reflect.Parameter param : handlerMethod.getMethod().getParameters()) {
                        if (param.isAnnotationPresent(AuthenticationPrincipal.class)) {
                            // Match by name to remove it
                            if (p.getName().equals(param.getName())) {
                                return true;
                            }
                        }
                    }
                    return false;
                });
            }

            return operation;
        };
    }
}

