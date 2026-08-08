package com.security.passwordmanager.helpers.impl;

import com.security.passwordmanager.helpers.TokenGenerator;
import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

@Component
public class TokenGeneratorImpl implements TokenGenerator {

    private final SecureRandom secureRandom = new SecureRandom();
    private final Base64.Encoder base64UrlEncoder = Base64.getUrlEncoder().withoutPadding();
    private final Base32 base32 = new Base32();
    private final int TOTP_SECRET_BYTES = 20;

    public String generateRefreshToken(int byteLength) {
        byte[] randomBytes = new byte[byteLength];
        secureRandom.nextBytes(randomBytes);
        return base64UrlEncoder.encodeToString(randomBytes);
    }

    public String generateRandomToken(int length) {
        String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int index = secureRandom.nextInt(charset.length());
            sb.append(charset.charAt(index));
        }

        return sb.toString();
    }

    @Override
    public String generateTotpSecret() {
        byte[] randomBytes = new byte[TOTP_SECRET_BYTES];
        secureRandom.nextBytes(randomBytes);
        return base32.encodeToString(randomBytes);
    }
}
