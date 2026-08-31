package xyz.segurapass.backend.config;

import xyz.segurapass.backend.redis.rate_limiting.LimitType;
import xyz.segurapass.backend.redis.rate_limiting.RateLimitRule;
import xyz.segurapass.backend.redis.rate_limiting.RateLimitRuleMatcher;
import xyz.segurapass.backend.redis.rate_limiting.RateLimitService;
import xyz.segurapass.backend.redis.RedisKeys;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.slf4j.MDC;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class RequestFilter extends OncePerRequestFilter {

    private final RateLimitRuleMatcher matcher;
    private final RateLimitService rateLimitService;
    private final JwtService jwtService;

    @SuppressWarnings("RedundantThrows")
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

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

            if (!isAllowedIp(rules, ip)) {
                respond429(response);
                return;
            }

            boolean requiresAuth = rules.stream()
                    .anyMatch(RateLimitRule::requiresAuth);

            if (requiresAuth) {
                String authHeader = request.getHeader("Authorization");
                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    respond401(response);
                    return;
                }

                String token = authHeader.substring(7);
                Claims claims = jwtService.validateToken(token);

                String userIdString = claims.getSubject();
                if (!isAllowedUser(rules, userIdString)) {
                    respond429(response);
                    return;
                }

                UUID userId = UUID.fromString(userIdString);
                UUID deviceId = UUID.fromString(
                        claims.get("deviceId", String.class)
                );

                AuthenticatedUser principal = new AuthenticatedUser(userId, deviceId);
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                principal,
                                null,
                                Collections.emptyList()
                        );

                SecurityContextHolder.getContext().setAuthentication(authentication);

                MDC.put("userId", userId.toString());
                MDC.put("deviceId", deviceId.toString());
            }

            filterChain.doFilter(request, response);

        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            respond500(response);
        } finally {
            MDC.remove("clientIp");
            MDC.remove("requestId");
            MDC.remove("userId");
            MDC.remove("deviceId");
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
            if (rule.limitType() == LimitType.IP) {
                String redisKey = RedisKeys.rateLimitIp(ip, rule.pattern());
                if (rateLimitService.isForbidden(redisKey, rule.limit(), rule.windowSeconds())) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean isAllowedUser(List<RateLimitRule> rules, String userIdString) {
        for (RateLimitRule rule : rules) {
            if (rule.limitType() == LimitType.USER) {
                String redisKey = RedisKeys.rateLimitUserId(userIdString, rule.pattern());
                if (rateLimitService.isForbidden(redisKey, rule.limit(), rule.windowSeconds())) {
                    return false;
                }
            }
        }
        return true;
    }

    private void respond401(HttpServletResponse response) throws IOException {
        response.setStatus(401);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"Missing or invalid Authorization header\"}");
    }

    private void respond429(HttpServletResponse response) throws IOException {
        response.setStatus(429);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"Rate limit exceeded\"}");
    }

    private void respond500(HttpServletResponse response) throws IOException {
        response.setStatus(500);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"Something went wrong\"}");
    }
}
