package com.security.passwordmanager.model.authorization;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.UUID;

public interface SessionDao extends JpaRepository<SessionEntity, Long> {
    SessionEntity findByUserEntityAndDeviceId(UserEntity userEntity, UUID deviceId);
    SessionEntity findByUserEntity_EmailAndDeviceId(String email, UUID deviceId);
    void deleteByExpiryTimeLessThan(Instant expiryTime);
}
