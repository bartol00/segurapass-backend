package com.security.passwordmanager.helpers.impl;

import com.security.passwordmanager.config.MfaConfig;
import com.security.passwordmanager.helpers.EncryptionService;
import com.security.passwordmanager.redis.entities.TotpRedisEntity;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class EncryptionServiceImpl implements EncryptionService {

    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final String CIPHER_INSTANCE = "AES/GCM/NoPadding";

    private final MfaConfig mfaConfig;
    private final SecureRandom secureRandom = new SecureRandom();

    public EncryptionServiceImpl(MfaConfig mfaConfig) {
        this.mfaConfig = mfaConfig;
    }

    @Override
    public TotpRedisEntity encryptTotpSecret(String totpSecret) throws Exception {
        SecretKey secretKey = mfaConfig.getSecretKey();

        byte[] iv = new byte[GCM_NONCE_LENGTH];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] ciphertext = cipher.doFinal(
                totpSecret.getBytes(StandardCharsets.UTF_8)
        );

        return new TotpRedisEntity(
                Base64.getEncoder().encodeToString(ciphertext),
                Base64.getEncoder().encodeToString(iv)
        );
    }

    @Override
    public byte[] decryptTotpSecret(String encryptedSecret, String ivStr) throws Exception {
        SecretKey secretKey = mfaConfig.getSecretKey();

        byte[] ciphertext = Base64.getDecoder().decode(encryptedSecret);
        byte[] iv = Base64.getDecoder().decode(ivStr);

        Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        return cipher.doFinal(ciphertext);
    }

}
