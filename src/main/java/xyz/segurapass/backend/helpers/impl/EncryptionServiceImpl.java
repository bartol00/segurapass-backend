package xyz.segurapass.backend.helpers.impl;

import xyz.segurapass.backend.config.MfaConfig;
import xyz.segurapass.backend.helpers.EncryptionService;
import xyz.segurapass.backend.redis.entities.TotpRedisEntity;
import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

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

        byte[] ciphertext = cipher.doFinal(totpSecret.getBytes(StandardCharsets.UTF_8));

        return new TotpRedisEntity(
                ciphertext,
                iv
        );
    }

    @Override
    public byte[] decryptTotpSecret(byte[] ciphertext, byte[] iv) throws Exception {
        SecretKey secretKey = mfaConfig.getSecretKey();

        Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        byte[] plaintextBytes = cipher.doFinal(ciphertext);
        String totpSecret = new String(
                plaintextBytes,
                StandardCharsets.UTF_8
        );
        return new Base32().decode(totpSecret);
    }

}
