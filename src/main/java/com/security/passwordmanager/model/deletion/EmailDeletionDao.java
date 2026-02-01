package com.security.passwordmanager.model.deletion;

import com.security.passwordmanager.model.authorization.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailDeletionDao extends JpaRepository<EmailDeletionEntity, Long> {
    EmailDeletionEntity findByToken(String token);
    boolean existsByUserEntity(UserEntity userEntity);
}
