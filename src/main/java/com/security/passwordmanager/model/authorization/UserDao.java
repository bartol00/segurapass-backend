package com.security.passwordmanager.model.authorization;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.UUID;

public interface UserDao extends JpaRepository<UserEntity, Long> {
    boolean existsByEmail(String email);
    UserEntity findByEmail(String email);
    UserEntity findByUserId(UUID userId);
    long deleteByLastLoginLessThan(Instant lastLogin);
    void deleteByUserId(UUID userId);
}
