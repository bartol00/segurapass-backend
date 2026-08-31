package xyz.segurapass.backend;

import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import xyz.segurapass.api.authorization.*;
import xyz.segurapass.backend.controller.AuthorizationController;
import xyz.segurapass.backend.config.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static xyz.segurapass.backend.shared.HelperMethods.*;

@SpringBootTest
@AutoConfigureMockMvc
class RateLimitIT extends AbstractTestInitializer {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private StringRedisTemplate redisTemplate;
    @Autowired
    private JwtService jwtService;

    private static final String PATH = "/api/authorization/login/start";
    private static final String IP_KEY_PREFIX =
            "segurapass:rate_limit:ip:";

    @BeforeEach
    void cleanup() {
        redisTemplate.delete(redisTemplate.keys("segurapass:rate_limit:*"));
    }

    @TestConfiguration
    static class MockControllerConfig {
        @Bean
        @Primary
        public AuthorizationController authorizationController() {
            return new AuthorizationController(null) {
                @Override
                public ResponseEntity<LoginStartResp> loginUserStart(LoginStartReq req) {
                    return ResponseEntity.ok().build();
                }
            };
        }
    }

    @Test
    void shouldCreateRedisKeyOnRequest() throws Exception {
        mockMvc.perform(post(PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginStartRequestJson()))
                .andExpect(status().isOk());

        Set<String> keys = redisTemplate.keys(IP_KEY_PREFIX + "127.0.0.1:/api/authorization/login/**");

        assertNotNull(keys);
        assertFalse(keys.isEmpty());
    }

    @Test
    void shouldIncrementCounterInRedis() throws Exception {
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post(PATH)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginStartRequestJson()))
                    .andExpect(status().isOk());
        }

        Set<String> keys = redisTemplate.keys(IP_KEY_PREFIX + "127.0.0.1:/api/authorization/login/**");
        assertEquals(1, keys.size());

        String key = keys.iterator().next();

        String value = redisTemplate.opsForValue().get(key);
        assertEquals("3", value);
    }

    @Test
    void shouldSetTtlOnRateLimitKey() throws Exception {
        mockMvc.perform(post(PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginStartRequestJson()))
                .andExpect(status().isOk());

        String key = redisTemplate.keys(IP_KEY_PREFIX + "127.0.0.1:/api/authorization/login/**")
                .iterator().next();

        Long ttl = redisTemplate.getExpire(key);

        assertThat(ttl).isGreaterThan(0);
        assertThat(ttl).isLessThanOrEqualTo(60);
    }

    @Test
    void shouldBlockAfterLimit() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post(PATH)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginStartRequestJson()))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(post(PATH))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void shouldResetAfterTtlExpires() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post(PATH)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginStartRequestJson()))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(post(PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginStartRequestJson()))
                .andExpect(status().isTooManyRequests());

        Thread.sleep(4000);

        mockMvc.perform(post(PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginStartRequestJson()))
                .andExpect(status().isOk());
    }

    @Test
    void shouldApplyUserRateLimit() throws Exception {
        Map<String, Object> claims = new HashMap<>();
        claims.put("deviceId", UUID.randomUUID());
        String token = generateJwt(
                jwtService.generateToken(UUID.randomUUID().toString(), claims, 180)
        );

        for (int i = 0; i < 50; i++) {
            mockMvc.perform(get("/api/credentials/get")
                            .header("Authorization", token))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(get("/api/credentials/get")
                        .header("Authorization", token))
                .andExpect(status().isTooManyRequests());
    }

}