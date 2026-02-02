package com.security.passwordmanager.helpers;

public interface TokenHasher {
    String hashToken(String token);
    boolean verifyToken(String token, String storedHash);
    String generateSha256(String input);
}
