package com.security.passwordmanager.helpers;

public interface TokenGenerator {
    String generateRefreshToken(int byteLength);
    String generateEmailVerifier();
}
