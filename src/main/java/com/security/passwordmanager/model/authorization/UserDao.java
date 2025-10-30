package com.security.passwordmanager.model.authorization;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface UserDao extends JpaRepository<UserEntity, Long> {
    boolean existsByEmail(String email);
    UserEntity findByEmail(String email);
    // List<UserEntity> findByVerificationExpiryTimeLessThanAndEmailVerified(Instant verificationExpiryTime, Boolean emailVerified);
    UserEntity findByVerificationString(String verificationString);
    void deleteByVerificationExpiryTimeLessThanAndEmailVerified(Instant verificationExpiryTime, Boolean emailVerified);
}
