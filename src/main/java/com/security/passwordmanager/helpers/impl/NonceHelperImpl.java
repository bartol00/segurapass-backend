package com.security.passwordmanager.helpers.impl;

import com.security.passwordmanager.helpers.NonceHelper;
import com.security.passwordmanager.helpers.TokenGenerator;
import com.security.passwordmanager.redis.RedisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.function.Function;

@Service
public class NonceHelperImpl implements NonceHelper {

    @Autowired
    private TokenGenerator tokenGenerator;
    @Autowired
    private RedisService redisService;

    @Override
    public String generateNonce(Object writeEntity, Function<String, String> action) {
        String nonce = tokenGenerator.generateRandomToken(48);
        String redisKey = action.apply(nonce);
        redisService.save(redisKey, writeEntity, Duration.of(60, ChronoUnit.SECONDS));
        return nonce;
    }
}
