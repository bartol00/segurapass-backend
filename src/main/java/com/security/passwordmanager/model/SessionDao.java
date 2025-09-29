package com.security.passwordmanager.model;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface SessionDao extends JpaRepository<SessionEntity, Long> {
    List<SessionEntity> findByExpiryTimeLessThanEqual(Instant expiryTime);
}
