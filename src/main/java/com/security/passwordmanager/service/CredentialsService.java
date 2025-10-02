package com.security.passwordmanager.service;

import com.security.passwordmanager.api.credentials.CredentialsReq;
import com.security.passwordmanager.api.error.ApiError;
import com.security.passwordmanager.api.error.ApiErrorEnum;
import com.security.passwordmanager.mapper.CredentialMapper;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.credentials.CredentialsDao;
import com.security.passwordmanager.model.credentials.CredentialsEntity;
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

    public ResponseEntity<?> getCredentials(String email, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("website").ascending());
        Page<CredentialsEntity> credentialsEntityPage = credentialsDao.findByUserEntity_Email(email, pageable);
        return ResponseEntity.ok(mapper.toCredentialsRespPage(credentialsEntityPage));
    }

    public ResponseEntity<?> getCredentialById(UUID id, String email) {
        CredentialsEntity credentialsEntity = credentialsDao.findByCredentialsIdAndUserEntity_Email(id, email);
        if (credentialsEntity == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.CREDENTIAL_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }
        return ResponseEntity.ok(mapper.toCredentialsResp(credentialsEntity));
    }

    public ResponseEntity<?> createCredentials(CredentialsReq req, String email) {
        UserEntity userEntity = userDao.findByEmail(email);

        CredentialsEntity credentialsEntity = mapper.toCredentialsEntity(req);
        credentialsEntity.setUserEntity(userEntity);
        credentialsEntity.setCredentialsId(UUID.randomUUID());
        credentialsEntity.setLastUpdated(Instant.now());

        credentialsEntity = credentialsDao.save(credentialsEntity);

        return ResponseEntity.ok(mapper.toCredentialsResp(credentialsEntity));
    }

    public ResponseEntity<?> updateCredentials(UUID id, CredentialsReq req, String email) {
        CredentialsEntity entity = credentialsDao.findByCredentialsIdAndUserEntity_Email(id, email);
        if (entity == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.CREDENTIAL_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        if (req.getWebsite() != null && !req.getWebsite().isBlank()) {
            entity.setWebsite(req.getWebsite());
        }
        if (req.getUsername() != null && !req.getUsername().isBlank()) {
            entity.setUsername(req.getUsername());
        }
        if (req.getPassword() != null && !req.getPassword().isBlank()) {
            entity.setPassword(req.getPassword());
        }
        if (req.getIv() != null && !req.getIv().isBlank()) {
            entity.setIv(req.getIv());
        }

        entity = credentialsDao.save(entity);

        return ResponseEntity.ok(mapper.toCredentialsResp(entity));
    }

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
