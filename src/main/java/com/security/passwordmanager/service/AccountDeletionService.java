package com.security.passwordmanager.service;

import com.security.passwordmanager.api.deletion.EmailDeletionStartReq;
import com.security.passwordmanager.api.error.ApiError;
import com.security.passwordmanager.api.error.ApiErrorEnum;
import com.security.passwordmanager.config.EmailService;
import com.security.passwordmanager.config.TokenGenerator;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.deletion.EmailDeletionDao;
import com.security.passwordmanager.model.deletion.EmailDeletionEntity;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
@RequiredArgsConstructor
public class AccountDeletionService {

    private final UserDao userDao;
    private final EmailDeletionDao emailDeletionDao;

    private final EmailService emailService;

    public void startDeletionEmail(EmailDeletionStartReq req) {
        UserEntity userEntity = userDao.findByEmail(req.getEmail());
        if (userEntity == null) {
            return;
        }
        if (emailDeletionDao.existsByUserEntity(userEntity)) {
            return;
        }

        String deletionToken = TokenGenerator.generateEmailVerifier();

        EmailDeletionEntity emailDeletionEntity = new EmailDeletionEntity();
        emailDeletionEntity.setToken(deletionToken);
        emailDeletionEntity.setTokenExpiry(Instant.now().plus(15, ChronoUnit.MINUTES));
        emailDeletionEntity.setUserEntity(userEntity);

        emailDeletionDao.save(emailDeletionEntity);

        emailService.sendDeletionEmail(req.getEmail(), deletionToken);
    }

    @Transactional
    public ResponseEntity<?> completeDeletionEmail(String token) {
        EmailDeletionEntity emailDeletionEntity = emailDeletionDao.findByToken(token);
        if (emailDeletionEntity == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_DELETION_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }
        if (emailDeletionEntity.getTokenExpiry().isBefore(Instant.now())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_DELETION_EXPIRED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        userDao.delete(emailDeletionEntity.getUserEntity());

        return ResponseEntity.ok(null);
    }

}
