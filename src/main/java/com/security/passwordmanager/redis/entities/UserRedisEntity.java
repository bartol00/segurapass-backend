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
    private String saltAuth;
    private String verifier;
    private String vaultKey;
    private String ivVaultKey;
    private String saltKey;
    private String saltHkdf;
    private String privateSigningKey;
    private String publicSigningKey;
    private String ivPrivateSigningKey;
    private Instant creationTime;
}
