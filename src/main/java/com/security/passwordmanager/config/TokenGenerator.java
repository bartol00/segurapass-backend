package com.security.passwordmanager.config;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

@Component
public class TokenGenerator {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64UrlEncoder = Base64.getUrlEncoder().withoutPadding();

    public static String generateRefreshToken(int byteLength) {
        byte[] randomBytes = new byte[byteLength];
        secureRandom.nextBytes(randomBytes);
        return base64UrlEncoder.encodeToString(randomBytes);
    }
}
