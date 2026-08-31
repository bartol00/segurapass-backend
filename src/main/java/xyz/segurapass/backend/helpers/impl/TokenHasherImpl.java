package xyz.segurapass.backend.helpers.impl;

import xyz.segurapass.backend.helpers.TokenHasher;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Component
public class TokenHasherImpl implements TokenHasher {

    private final String emailHashSalt;

    public TokenHasherImpl(@Qualifier("emailHashSalt") String emailHashSalt) {
        this.emailHashSalt = emailHashSalt;
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
