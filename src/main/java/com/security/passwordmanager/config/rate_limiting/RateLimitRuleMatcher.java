package com.security.passwordmanager.config.rate_limiting;

import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.List;

@Component
public class RateLimitRuleMatcher {

    private final List<RateLimitRule> rules;
    private final AntPathMatcher matcher = new AntPathMatcher();

    public RateLimitRuleMatcher(List<RateLimitRule> rules) {
        this.rules = rules;
    }

    public List<RateLimitRule> match(String path) {
        return rules.stream()
                .filter(rule -> matcher.match(rule.getPattern(), path))
                .toList();
    }
}
