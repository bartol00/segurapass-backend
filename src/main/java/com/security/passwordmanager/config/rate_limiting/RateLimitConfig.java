package com.security.passwordmanager.config.rate_limiting;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class RateLimitConfig {

    @Value("${app.rate-limiting.ip-enabled}")
    private boolean ipRulesEnabled;

    @Bean
    public List<RateLimitRule> rateLimitRules() {
        List<RateLimitRule> rules = new ArrayList<>(List.of(
                new RateLimitRule("/api/deletion/authorized/**", 10, 60, LimitType.USER, true),
                new RateLimitRule("/api/credentials/**", 50, 60, LimitType.USER, true)
        ));

        if (ipRulesEnabled) {
            rules.addAll(List.of(
                    new RateLimitRule("/api/deletion/**", 20, 60, LimitType.IP, false),
                    new RateLimitRule("/api/authorization/register", 10, 60, LimitType.IP, false),
                    new RateLimitRule("/api/authorization/login/**", 10, 60, LimitType.IP, false),
                    new RateLimitRule("/api/authorization/**", 30, 60, LimitType.IP, false),
                    new RateLimitRule("/.well-known/**", 100, 60, LimitType.IP, false),
                    new RateLimitRule("/api/uptime", 100, 60, LimitType.IP, false),
                    new RateLimitRule("/api/versions/**", 100, 60, LimitType.IP, false)
            ));
        }

        return List.copyOf(rules);
    }

}
