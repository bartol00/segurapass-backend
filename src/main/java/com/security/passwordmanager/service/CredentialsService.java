package com.security.passwordmanager.service;

import com.security.passwordmanager.api.credentials.CredentialsReq;
import com.security.passwordmanager.api.credentials.CredentialsResp;
import com.security.passwordmanager.exceptions.CredentialsException;
import com.security.passwordmanager.helpers.TokenHasher;
import com.security.passwordmanager.mapper.CredentialMapper;
import com.security.passwordmanager.model.audit.AuditAction;
import com.security.passwordmanager.model.audit.AuditLogDao;
import com.security.passwordmanager.model.audit.AuditLogEntity;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.credentials.CredentialsDao;
import com.security.passwordmanager.model.credentials.CredentialsEntity;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
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
    private final AuditLogDao auditLogDao;
    private final TokenHasher tokenHasher;

    @Transactional
    public ResponseEntity<Page<CredentialsResp>> getCredentials(String email, int page, int size) {
        log.info("Get Credentials for user {} - Service", tokenHasher.generateSha256Email(email));

        Pageable pageable = PageRequest.of(page, size);
        Page<CredentialsEntity> credentialsEntityPage = credentialsDao.findByUserEntity_Email(email, pageable);
        return ResponseEntity.ok(mapper.toCredentialsRespPage(credentialsEntityPage));
    }

    @Transactional
    public ResponseEntity<CredentialsResp> getCredentialById(UUID id, String email) {
        log.info("Get Credentials By ID for user {} - Service", tokenHasher.generateSha256Email(email));

        CredentialsEntity credentialsEntity = credentialsDao.findByCredentialsIdAndUserEntity_Email(id, email);
        if (credentialsEntity == null) {
            throw new CredentialsException(CREDENTIAL_NOT_EXISTS);
        }
        return ResponseEntity.ok(mapper.toCredentialsResp(credentialsEntity));
    }

    @Transactional
    public ResponseEntity<CredentialsResp> createCredentials(CredentialsReq req, String email) {
        log.info("Create Credentials for user {} - Service", tokenHasher.generateSha256Email(email));

        UserEntity userEntity = userDao.findByEmail(email);

        CredentialsEntity credentialsEntity = mapper.toCredentialsEntity(req);
        credentialsEntity.setUserEntity(userEntity);
        credentialsEntity.setCredentialsId(UUID.randomUUID());
        credentialsEntity.setLastUpdated(Instant.now());

        credentialsEntity = credentialsDao.save(credentialsEntity);

        AuditLogEntity auditLogEntity = new AuditLogEntity();
        auditLogEntity.setUserId(userEntity.getUserId());
        auditLogEntity.setTimestamp(Instant.now());
        auditLogEntity.setAction(AuditAction.CREDENTIAL_CREATED);
        auditLogEntity.setIpAddress(MDC.get("clientIp"));
        auditLogEntity.setSuccess(true);
        auditLogEntity.setComment("Created credential with ID: " + credentialsEntity.getCredentialsId());
        auditLogDao.save(auditLogEntity);

        return ResponseEntity.ok(mapper.toCredentialsResp(credentialsEntity));
    }

    @Transactional
    public ResponseEntity<CredentialsResp> updateCredentials(UUID id, CredentialsReq req, String email) {
        log.info("Update Credentials for user {} - Service", tokenHasher.generateSha256Email(email));

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

        AuditLogEntity auditLogEntity = new AuditLogEntity();
        auditLogEntity.setUserId(userDao.findByEmail(email).getUserId());
        auditLogEntity.setTimestamp(Instant.now());
        auditLogEntity.setAction(AuditAction.CREDENTIAL_UPDATED);
        auditLogEntity.setIpAddress(MDC.get("clientIp"));
        auditLogEntity.setSuccess(true);
        auditLogEntity.setComment("Updated credential with ID: " + entity.getCredentialsId());
        auditLogDao.save(auditLogEntity);

        return ResponseEntity.ok(mapper.toCredentialsResp(entity));
    }

    @Transactional
    public ResponseEntity<Void> deleteCredentials(UUID id, String email) {
        log.info("Delete Credentials for user {} - Service", tokenHasher.generateSha256Email(email));

        CredentialsEntity credentialsEntity = credentialsDao.findByCredentialsIdAndUserEntity_Email(id, email);
        if (credentialsEntity == null) {
            throw new CredentialsException(CREDENTIAL_NOT_EXISTS);
        }

        credentialsDao.delete(credentialsEntity);

        AuditLogEntity auditLogEntity = new AuditLogEntity();
        auditLogEntity.setUserId(userDao.findByEmail(email).getUserId());
        auditLogEntity.setTimestamp(Instant.now());
        auditLogEntity.setAction(AuditAction.CREDENTIAL_DELETED);
        auditLogEntity.setIpAddress(MDC.get("clientIp"));
        auditLogEntity.setSuccess(true);
        auditLogEntity.setComment("Deleted credential with ID: " + credentialsEntity.getCredentialsId());
        auditLogDao.save(auditLogEntity);

        return ResponseEntity.ok(null);
    }

}
