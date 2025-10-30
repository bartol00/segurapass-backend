package com.security.passwordmanager.model.authorization;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.UUID;

public interface SrpDao extends JpaRepository<SrpEntity, Long> {
    SrpEntity findByUserEntity_EmailAndDeviceId(String email, UUID deviceId);
    // List<SrpEntity> findByExpiryTimeLessThan(Instant expiryTime);
    void deleteByExpiryTimeLessThan(Instant expiryTime);
}