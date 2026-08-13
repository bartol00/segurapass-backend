package com.security.passwordmanager.redis.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TotpRedisEntity {
    private String encryptedTotpSecret;
    private String iv;
}
