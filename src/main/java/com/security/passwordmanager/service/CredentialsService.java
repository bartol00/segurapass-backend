package com.security.passwordmanager.service;

import com.security.passwordmanager.api.credentials.CredentialsReq;
import com.security.passwordmanager.api.credentials.CredentialsResp;
import com.security.passwordmanager.exceptions.CredentialsException;
import com.security.passwordmanager.mapper.CredentialMapper;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.credentials.CredentialsDao;
import com.security.passwordmanager.model.credentials.CredentialsEntity;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

import static com.security.passwordmanager.exceptions.ErrorEnum.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialsService {

    private final CredentialMapper mapper;

    private final CredentialsDao credentialsDao;
    private final UserDao userDao;

    @Transactional
    public ResponseEntity<Page<CredentialsResp>> getCredentials(String email, int page, int size) {
        log.info("Get Credentials - Service");

        Pageable pageable = PageRequest.of(page, size);
        Page<CredentialsEntity> credentialsEntityPage = credentialsDao.findByUserEntity_Email(email, pageable);
        return ResponseEntity.ok(mapper.toCredentialsRespPage(credentialsEntityPage));
    }

    @Transactional
    public ResponseEntity<CredentialsResp> getCredentialById(UUID id, String email) {
        log.info("Get Credentials By ID - Service");

        CredentialsEntity credentialsEntity = credentialsDao.findByCredentialsIdAndUserEntity_Email(id, email);
        if (credentialsEntity == null) {
            throw new CredentialsException(CREDENTIAL_NOT_EXISTS);
        }
        return ResponseEntity.ok(mapper.toCredentialsResp(credentialsEntity));
    }

    @Transactional
    public ResponseEntity<CredentialsResp> createCredentials(CredentialsReq req, String email) {
        log.info("Create Credentials - Service");

        UserEntity userEntity = userDao.findByEmail(email);

        CredentialsEntity credentialsEntity = mapper.toCredentialsEntity(req);
        credentialsEntity.setUserEntity(userEntity);
        credentialsEntity.setCredentialsId(UUID.randomUUID());
        credentialsEntity.setLastUpdated(Instant.now());

        credentialsEntity = credentialsDao.save(credentialsEntity);

        return ResponseEntity.ok(mapper.toCredentialsResp(credentialsEntity));
    }

    @Transactional
    public ResponseEntity<CredentialsResp> updateCredentials(UUID id, CredentialsReq req, String email) {
        log.info("Update Credentials - Service");

        CredentialsEntity entity = credentialsDao.findByCredentialsIdAndUserEntity_Email(id, email);
        if (entity == null) {
            throw new CredentialsException(CREDENTIAL_NOT_EXISTS);
        }

        if (req.getWebsite() != null && !req.getWebsite().isBlank()) {
            if (req.getIvWebsite() == null || req.getIvWebsite().isBlank()) {
                throw new CredentialsException(CREDENTIAL_UPDATE_IV_MISSING);
            }
            entity.setWebsite(req.getWebsite());
            entity.setIvWebsite(req.getIvWebsite());
        }
        if (req.getUsername() != null && !req.getUsername().isBlank()) {
            if (req.getIvUsername() == null || req.getIvUsername().isBlank()) {
                throw new CredentialsException(CREDENTIAL_UPDATE_IV_MISSING);
            }
            entity.setUsername(req.getUsername());
            entity.setIvUsername(req.getIvUsername());
        }
        if (req.getPassword() != null && !req.getPassword().isBlank()) {
            if (req.getIvPassword() == null || req.getIvPassword().isBlank()) {
                throw new CredentialsException(CREDENTIAL_UPDATE_IV_MISSING);
            }
            entity.setPassword(req.getPassword());
            entity.setIvPassword(req.getIvPassword());
        }
        entity.setLastUpdated(Instant.now());

        entity = credentialsDao.save(entity);

        return ResponseEntity.ok(mapper.toCredentialsResp(entity));
    }

    @Transactional
    public ResponseEntity<Void> deleteCredentials(UUID id, String email) {
        log.info("Delete Credentials - Service");

        CredentialsEntity credentialsEntity = credentialsDao.findByCredentialsIdAndUserEntity_Email(id, email);
        if (credentialsEntity == null) {
            throw new CredentialsException(CREDENTIAL_NOT_EXISTS);
        }

        credentialsDao.delete(credentialsEntity);

        return ResponseEntity.ok(null);
    }

}
