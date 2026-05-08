package com.security.passwordmanager.model.credentials;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface CredentialsDao extends JpaRepository<CredentialsEntity, Long> {
    Page<CredentialsEntity> findByUserEntity_UserId(UUID userId, Pageable pageable);
    CredentialsEntity findByCredentialsIdAndUserEntity_UserId(UUID credentialsId, UUID userId);
}
