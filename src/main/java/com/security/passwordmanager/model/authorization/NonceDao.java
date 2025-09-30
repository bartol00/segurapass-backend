package com.security.passwordmanager.model.authorization;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface NonceDao extends JpaRepository<NonceEntity, Long> {
    NonceEntity findByUserEntityAndDeviceId(UserEntity userEntity, UUID deviceId);
    List<NonceEntity> findByNonceExpiryLessThanEqual(Instant nonceExpiry);
}
