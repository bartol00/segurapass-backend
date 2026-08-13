package com.security.passwordmanager.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;

@Configuration
@Getter
public class MfaConfig {

    private final SecretKey secretKey;

    public MfaConfig(@Value("${app.security.totp-encryption-key}") String keyHex) {
        byte[] keyBytes = HexFormat.of().parseHex(keyHex);
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("TOTP encryption key must be exactly 32 bytes");
        }
        this.secretKey = new SecretKeySpec(keyBytes, "AES");
    }

}
