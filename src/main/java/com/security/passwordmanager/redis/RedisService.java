package com.security.passwordmanager.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    public void save(String key, Object value, Duration ttl) {
        try {
            String json = objectMapper.writeValueAsString(value);

            redisTemplate.opsForValue().set(
                    key,
                    json,
                    ttl
            );
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public <T> T get(String key, Class<T> clazz) {
        try {
            String json = redisTemplate.opsForValue().get(key);

            if (json == null) {
                return null;
            }

            return objectMapper.readValue(json, clazz);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public boolean exists(String key) {
        return redisTemplate.hasKey(key);
    }

    public void delete(String key) {
        redisTemplate.delete(key);
    }

    public void clearAll() {
        assert redisTemplate.getConnectionFactory() != null;
        redisTemplate.getConnectionFactory()
                .getConnection()
                .serverCommands()
                .flushDb();
    }
}