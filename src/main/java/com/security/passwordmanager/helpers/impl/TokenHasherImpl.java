package com.security.passwordmanager.helpers.impl;

import com.security.passwordmanager.helpers.TokenHasher;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Component
public class TokenHasherImpl implements TokenHasher {

    private final Argon2PasswordEncoder encoder;
    private final String emailHashSalt;

    public TokenHasherImpl(@Qualifier("emailHashSalt") String emailHashSalt) {
        this.encoder = new Argon2PasswordEncoder(16, 32, 1, 65536, 3);
        this.emailHashSalt = emailHashSalt;
    }

    public String hashToken(String token) {
        return encoder.encode(token);
    }

    public boolean verifyToken(String token, String storedHash) {
        return encoder.matches(token, storedHash);
    }

    public String generateSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();

        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    @Override
    public String generateSha256Email(String email) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            String normalized = email.trim().toLowerCase();
            String salted = emailHashSalt + normalized;
            byte[] hash = digest.digest(salted.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();

        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
