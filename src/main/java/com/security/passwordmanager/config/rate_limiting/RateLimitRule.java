package com.security.passwordmanager.config.rate_limiting;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RateLimitRule {
    private final String pattern;
    private final int limit;
    private final int windowSeconds;
    private final LimitType limitType;
    private final boolean requiresAuth;
}
