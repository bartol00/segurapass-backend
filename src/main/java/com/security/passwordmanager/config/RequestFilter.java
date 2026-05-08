package com.security.passwordmanager.config;

import com.security.passwordmanager.config.rate_limiting.LimitType;
import com.security.passwordmanager.config.rate_limiting.RateLimitRule;
import com.security.passwordmanager.config.rate_limiting.RateLimitRuleMatcher;
import com.security.passwordmanager.config.rate_limiting.RateLimitService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class RequestFilter extends OncePerRequestFilter {

    private final PublicKey publicKey;
    private final RateLimitRuleMatcher matcher;
    private final RateLimitService rateLimitService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String ip = extractClientIp(request);
        MDC.put("clientIp", ip);
        String requestId = extractRequestId(request);
        MDC.put("requestId", requestId);

        response.setHeader("X-Request-ID", requestId);

        try {
            String path = request.getRequestURI();
            List<RateLimitRule> rules = matcher.match(path);

            if (rules.isEmpty()) {
                filterChain.doFilter(request, response);
                return;
            }

            boolean requiresAuth = rules.stream()
                    .anyMatch(RateLimitRule::isRequiresAuth);

            if (!isAllowedIp(rules, ip)) {
                respond429(response);
                return;
            }

            if (requiresAuth) {
                String authHeader = request.getHeader("Authorization");
                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    respond401(response, "{\"error\": \"Missing or invalid Authorization header\"}");
                    return;
                }

                String token = authHeader.substring(7);

                Jws<Claims> jws = Jwts.parser()
                        .verifyWith(publicKey)
                        .build()
                        .parseSignedClaims(token);

                Claims claims = jws.getPayload();
                String userIdString = claims.getSubject();

                if (!isAllowedUser(rules, userIdString)) {
                    respond429(response);
                    return;
                }

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(UUID.fromString(userIdString), null, Collections.emptyList());

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            filterChain.doFilter(request, response);

        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            respond401(response, "{\"error\": \"Invalid JWT token\"}");
        } finally {
            MDC.remove("clientIp");
            MDC.remove("requestId");
        }
    }

    private String extractClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");

        if (xfHeader != null && !xfHeader.isEmpty()) {
            return xfHeader.split(",")[0].trim(); // first IP = original client
        }

        return request.getRemoteAddr();
    }

    private String extractRequestId(HttpServletRequest request) {
        String requestIdHeader = request.getHeader("X-Request-ID");

        if (requestIdHeader != null && !requestIdHeader.isEmpty() && requestIdHeader.length() <= 100) {
            return requestIdHeader;
        }

        return UUID.randomUUID().toString();
    }

    private boolean isAllowedIp(List<RateLimitRule> rules, String ip) {
        for (RateLimitRule rule : rules) {
            if (rule.getLimitType() == LimitType.IP) {
                String key = "segurapass:rate_limit:ip:" + ip + ":" + rule.getPattern();
                if (!rateLimitService.isAllowed(key, rule.getLimit(), rule.getWindowSeconds())) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean isAllowedUser(List<RateLimitRule> rules, String userIdString) {
        for (RateLimitRule rule : rules) {
            if (rule.getLimitType() == LimitType.USER) {
                String key = "segurapass:rate_limit:user:" + userIdString + ":" + rule.getPattern();
                if (!rateLimitService.isAllowed(key, rule.getLimit(), rule.getWindowSeconds())) {
                    return false;
                }
            }
        }
        return true;
    }

    private void respond401(HttpServletResponse response, String error) throws IOException {
        response.setStatus(401);
        response.setContentType("application/json");
        response.getWriter().write(error);
    }

    private void respond429(HttpServletResponse response) throws IOException {
        response.setStatus(429);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"Rate limit exceeded\"}");
    }
}
