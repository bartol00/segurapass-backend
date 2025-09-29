package com.security.passwordmanager.model;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface SessionDao extends JpaRepository<SessionEntity, Long> {
    List<SessionEntity> findByExpiryTimeLessThanEqual(Instant expiryTime);
    SessionEntity findByUserEntityAndDeviceId(UserEntity userEntity, UUID deviceId);
}
