package xyz.segurapass.backend.helpers;

import xyz.segurapass.backend.redis.entities.TotpRedisEntity;

public interface EncryptionService {
    TotpRedisEntity encryptTotpSecret(String totpSecret) throws Exception;
    byte[] decryptTotpSecret(byte[] ciphertext, byte[] iv) throws Exception;
}
