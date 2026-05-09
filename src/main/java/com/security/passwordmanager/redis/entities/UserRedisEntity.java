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
    private String saltKey;
    private Instant creationTime;
}
