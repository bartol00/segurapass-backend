package com.security.passwordmanager.config;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class TokenHasher {
    private static final Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 65536, 3);

    public static String hashToken(String token) {
        return encoder.encode(token);
    }

    public static boolean verifyToken(String token, String storedHash) {
        return encoder.matches(token, storedHash);
    }
}
