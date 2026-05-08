package com.security.passwordmanager.model.authorization;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.UUID;

public interface UserDao extends JpaRepository<UserEntity, Long> {
    boolean existsByEmail(String email);
    UserEntity findByEmail(String email);
    UserEntity findByVerificationString(String verificationString);
    UserEntity findByUserId(UUID userId);
    void deleteByVerificationExpiryTimeLessThanAndEmailVerified(Instant verificationExpiryTime, Boolean emailVerified);
    void deleteByLastLoginLessThan(Instant lastLogin);
    void deleteByEmail(String email);
    void deleteByUserId(UUID userId);
}
