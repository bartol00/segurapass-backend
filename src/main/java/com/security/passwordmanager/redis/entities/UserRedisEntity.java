package com.security.passwordmanager.redis.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserRedisEntity {
    private UUID userId;
    private String email;
    private byte[] saltAuth;
    private String verifier;
    private byte[] vaultKey;
    private byte[] ivVaultKey;
    private byte[] saltKey;
    private byte[] saltHkdf;
    private byte[] privateSigningKey;
    private byte[] publicSigningKey;
    private byte[] ivPrivateSigningKey;
    private Instant creationTime;
}
