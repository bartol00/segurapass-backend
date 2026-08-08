package com.security.passwordmanager.helpers;

import com.security.passwordmanager.redis.entities.TotpRedisEntity;

public interface EncryptionService {
    TotpRedisEntity encryptTotpSecret(String totpSecret) throws Exception;
    byte[] decryptTotpSecret(String encryptedSecret, String ivStr) throws Exception;
}
