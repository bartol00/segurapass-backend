package xyz.segurapass.backend.redis.rate_limiting;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class RateLimitService {

    private final StringRedisTemplate redisTemplate;

    public RateLimitService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public boolean isForbidden(String key, int limit, int windowSeconds) {
        Long count = redisTemplate.opsForValue().increment(key);

        if (count == null) {
            return true;
        }

        if (count == 1) {
            redisTemplate.expire(key, Duration.ofSeconds(windowSeconds));
        }

        return count > limit;
    }

}
