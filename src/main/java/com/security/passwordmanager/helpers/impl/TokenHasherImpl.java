package com.security.passwordmanager.helpers.impl;

import com.security.passwordmanager.helpers.TokenHasher;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class TokenHasherImpl implements TokenHasher {
    private final Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 65536, 3);

    public String hashToken(String token) {
        return encoder.encode(token);
    }

    public boolean verifyToken(String token, String storedHash) {
        return encoder.matches(token, storedHash);
    }
}
