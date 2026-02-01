package com.security.passwordmanager.service;

import com.security.passwordmanager.api.credentials.CredentialsReq;
import com.security.passwordmanager.api.error.ApiError;
import com.security.passwordmanager.api.error.ApiErrorEnum;
import com.security.passwordmanager.mapper.CredentialMapper;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.credentials.CredentialsDao;
import com.security.passwordmanager.model.credentials.CredentialsEntity;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CredentialsService {

    private final CredentialMapper mapper;

    private final CredentialsDao credentialsDao;
    private final UserDao userDao;

    @Transactional
    public ResponseEntity<?> getCredentials(String email, int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<CredentialsEntity> credentialsEntityPage = credentialsDao.findByUserEntity_Email(email, pageable);
        return ResponseEntity.ok(mapper.toCredentialsRespPage(credentialsEntityPage));
    }

    @Transactional
    public ResponseEntity<?> getCredentialById(UUID id, String email) {
        CredentialsEntity credentialsEntity = credentialsDao.findByCredentialsIdAndUserEntity_Email(id, email);
        if (credentialsEntity == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.CREDENTIAL_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }
        return ResponseEntity.ok(mapper.toCredentialsResp(credentialsEntity));
    }

    @Transactional
    public ResponseEntity<?> createCredentials(CredentialsReq req, String email) {
        UserEntity userEntity = userDao.findByEmail(email);

        CredentialsEntity credentialsEntity = mapper.toCredentialsEntity(req);
        credentialsEntity.setUserEntity(userEntity);
        credentialsEntity.setCredentialsId(UUID.randomUUID());
        credentialsEntity.setLastUpdated(Instant.now());

        credentialsEntity = credentialsDao.save(credentialsEntity);

        return ResponseEntity.ok(mapper.toCredentialsResp(credentialsEntity));
    }

    @Transactional
    public ResponseEntity<?> updateCredentials(UUID id, CredentialsReq req, String email) {
        CredentialsEntity entity = credentialsDao.findByCredentialsIdAndUserEntity_Email(id, email);
        if (entity == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.CREDENTIAL_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        if (req.getWebsite() != null && !req.getWebsite().isBlank()) {
            if (req.getIvWebsite() == null || req.getIvWebsite().isBlank()) {
                ApiError apiError = new ApiError(ApiErrorEnum.CREDENTIAL_UPDATE_IV_MISSING);
                return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
            }
            entity.setWebsite(req.getWebsite());
            entity.setIvWebsite(req.getIvWebsite());
        }
        if (req.getUsername() != null && !req.getUsername().isBlank()) {
            if (req.getIvUsername() == null || req.getIvUsername().isBlank()) {
                ApiError apiError = new ApiError(ApiErrorEnum.CREDENTIAL_UPDATE_IV_MISSING);
                return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
            }
            entity.setUsername(req.getUsername());
            entity.setIvUsername(req.getIvUsername());
        }
        if (req.getPassword() != null && !req.getPassword().isBlank()) {
            if (req.getIvPassword() == null || req.getIvPassword().isBlank()) {
                ApiError apiError = new ApiError(ApiErrorEnum.CREDENTIAL_UPDATE_IV_MISSING);
                return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
            }
            entity.setPassword(req.getPassword());
            entity.setIvPassword(req.getIvPassword());
        }
        entity.setLastUpdated(Instant.now());

        entity = credentialsDao.save(entity);

        return ResponseEntity.ok(mapper.toCredentialsResp(entity));
    }

    @Transactional
    public ResponseEntity<?> deleteCredentials(UUID id, String email) {
        CredentialsEntity credentialsEntity = credentialsDao.findByCredentialsIdAndUserEntity_Email(id, email);
        if (credentialsEntity == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.CREDENTIAL_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        credentialsDao.delete(credentialsEntity);

        return ResponseEntity.ok(null);
    }

}
