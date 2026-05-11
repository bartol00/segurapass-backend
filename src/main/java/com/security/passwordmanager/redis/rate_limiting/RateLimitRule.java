package com.security.passwordmanager.redis.rate_limiting;

public record RateLimitRule(String pattern, int limit, int windowSeconds, LimitType limitType, boolean requiresAuth) {
}
