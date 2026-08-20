package com.security.passwordmanager.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.passwordmanager.helpers.SignatureService;
import com.security.passwordmanager.helpers.TokenGenerator;
import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.CredentialsWriteEntity;
import xyz.segurapass.api.credentials.*;
import com.security.passwordmanager.exceptions.CredentialsException;
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
import xyz.segurapass.api.credentials.CredentialsOperation;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.UUID;

import static com.security.passwordmanager.exceptions.enums.ErrorEnum.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialsService {

    private final CredentialMapper mapper;

    private final TokenGenerator tokenGenerator;
    private final RedisService redisService;
    private final SignatureService signatureService;

    private final CredentialsDao credentialsDao;
    private final UserDao userDao;
    private final AuditLogDao auditLogDao;
    private final ObjectMapper objectMapper;

    @Transactional
    public ResponseEntity<Page<CredentialsResp>> getCredentials(UUID userId, int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<CredentialsEntity> credentialsEntityPage = credentialsDao.findByUserEntity_UserId(userId, pageable);

        log.info("Get Credentials for user: {} - Service", userId);

        return ResponseEntity.ok(mapper.toCredentialsRespPage(credentialsEntityPage));
    }

    @Transactional
    public ResponseEntity<CredentialsResp> getCredentialById(UUID id, UUID userId) {
        CredentialsEntity credentialsEntity = credentialsDao.findByCredentialsIdAndUserEntity_UserId(id, userId);
        if (credentialsEntity == null) {
            throw new CredentialsException(CREDENTIAL_NOT_EXISTS);
        }

        log.info("Get Credentials By ID for user: {} - Service", userId);

        return ResponseEntity.ok(mapper.toCredentialsResp(credentialsEntity));
    }

    public ResponseEntity<NonceResp> createCredentialsStart(UUID userId, UUID deviceId) {
        String nonce = generateNonce(null, userId, deviceId, CredentialsOperation.CREATE);
        return ResponseEntity.ok(new NonceResp(nonce));
    }

    @Transactional
    public ResponseEntity<CredentialsResp> createCredentialsEnd(CredentialsReq req, UUID userId, UUID deviceId, String signature) {
        verifyNonceAndSignature(null, userId, deviceId, req, signature);

        UserEntity userEntity = userDao.findByUserId(userId);

        Instant now = Instant.now();

        CredentialsEntity credentialsEntity = mapper.toCredentialsEntity(req);
        credentialsEntity.setUserEntity(userEntity);
        credentialsEntity.setCredentialsId(UUID.randomUUID());
        credentialsEntity.setCreatedAt(now);
        credentialsEntity.setLastUpdated(now);
        credentialsEntity = credentialsDao.save(credentialsEntity);

        AuditLogEntity auditLogEntity = new AuditLogEntity();
        auditLogEntity.setUserId(userId);
        auditLogEntity.setTimestamp(now);
        auditLogEntity.setAction(AuditAction.CREDENTIAL_CREATED);
        auditLogEntity.setIpAddress(MDC.get("clientIp"));
        auditLogEntity.setSuccess(true);
        auditLogEntity.setComment("Created credential with ID: " + credentialsEntity.getCredentialsId());
        auditLogDao.save(auditLogEntity);

        log.info("Create Credentials End for user: {} - Service", userId);

        return ResponseEntity.ok(mapper.toCredentialsResp(credentialsEntity));
    }

    public ResponseEntity<NonceResp> updateCredentialsStart(UUID credentialsId, UUID userId, UUID deviceId) {
        String nonce = generateNonce(credentialsId, userId, deviceId, CredentialsOperation.UPDATE);
        return ResponseEntity.ok(new NonceResp(nonce));
    }

    @Transactional
    public ResponseEntity<CredentialsResp> updateCredentialsEnd(UUID id, CredentialsReq req, UUID userId, UUID deviceId,String signature) {
        verifyNonceAndSignature(id, userId, deviceId, req, signature);

        CredentialsEntity entity = credentialsDao.findByCredentialsIdAndUserEntity_UserId(id, userId);
        if (entity == null) {
            throw new CredentialsException(CREDENTIAL_NOT_EXISTS);
        }

        if (req.getWebsiteBytes() != null) {
            if (req.getIvWebsiteBytes() == null) {
                throw new CredentialsException(CREDENTIAL_UPDATE_IV_MISSING);
            }
            entity.setWebsiteBytes(req.getWebsiteBytes());
            entity.setIvWebsiteBytes(req.getIvWebsiteBytes());
        }
        if (req.getUsernameBytes() != null) {
            if (req.getIvUsernameBytes() == null) {
                throw new CredentialsException(CREDENTIAL_UPDATE_IV_MISSING);
            }
            entity.setUsernameBytes(req.getUsernameBytes());
            entity.setIvUsernameBytes(req.getIvUsernameBytes());
        }
        if (req.getPasswordBytes() != null) {
            if (req.getIvPasswordBytes() == null) {
                throw new CredentialsException(CREDENTIAL_UPDATE_IV_MISSING);
            }
            entity.setPasswordBytes(req.getPasswordBytes());
            entity.setIvPasswordBytes(req.getIvPasswordBytes());
        }
        Instant now = Instant.now();
        entity.setLastUpdated(now);
        entity = credentialsDao.save(entity);

        AuditLogEntity auditLogEntity = new AuditLogEntity();
        auditLogEntity.setUserId(userId);
        auditLogEntity.setTimestamp(now);
        auditLogEntity.setAction(AuditAction.CREDENTIAL_UPDATED);
        auditLogEntity.setIpAddress(MDC.get("clientIp"));
        auditLogEntity.setSuccess(true);
        auditLogEntity.setComment("Updated credential with ID: " + entity.getCredentialsId());
        auditLogDao.save(auditLogEntity);

        log.info("Update Credentials End for user: {} - Service", userId);

        return ResponseEntity.ok(mapper.toCredentialsResp(entity));
    }

    public ResponseEntity<NonceResp> deleteCredentialsStart(UUID credentialsId, UUID userId, UUID deviceId) {
        String nonce = generateNonce(credentialsId, userId, deviceId, CredentialsOperation.DELETE);
        return ResponseEntity.ok(new NonceResp(nonce));
    }

    @Transactional
    public ResponseEntity<Void> deleteCredentialsEnd(UUID id, CredentialsReq req, UUID userId, UUID deviceId, String signature) {
        verifyNonceAndSignature(id, userId, deviceId, req, signature);

        CredentialsEntity credentialsEntity = credentialsDao.findByCredentialsIdAndUserEntity_UserId(id, userId);
        if (credentialsEntity == null) {
            throw new CredentialsException(CREDENTIAL_NOT_EXISTS);
        }

        credentialsDao.delete(credentialsEntity);

        AuditLogEntity auditLogEntity = new AuditLogEntity();
        auditLogEntity.setUserId(userId);
        auditLogEntity.setTimestamp(Instant.now());
        auditLogEntity.setAction(AuditAction.CREDENTIAL_DELETED);
        auditLogEntity.setIpAddress(MDC.get("clientIp"));
        auditLogEntity.setSuccess(true);
        auditLogEntity.setComment("Deleted credential with ID: " + credentialsEntity.getCredentialsId());
        auditLogDao.save(auditLogEntity);

        log.info("Delete Credentials End for user: {} - Service", userId);

        return ResponseEntity.ok(null);
    }

    private String generateNonce(UUID credentialsId, UUID userId, UUID deviceId, CredentialsOperation operation) {
        String nonce = tokenGenerator.generateRandomToken(48);

        String redisKey = RedisKeys.credentialsNonce(nonce);
        CredentialsWriteEntity writeEntity = new CredentialsWriteEntity(
                userId,
                deviceId,
                operation,
                credentialsId
        );

        redisService.save(redisKey,writeEntity, Duration.of(60, ChronoUnit.SECONDS));

        return nonce;
    }

    private void verifyNonceAndSignature(
            UUID credentialsId,
            UUID userId,
            UUID deviceId,
            CredentialsReq req,
            String signature
    ) {
        if (req.getNonce() == null || req.getNonce().isEmpty()) {
            throw new CredentialsException(CREDENTIAL_NONCE_MISSING);
        }

        String redisKey = RedisKeys.credentialsNonce(req.getNonce());
        if (!redisService.exists(redisKey)) {
            throw new CredentialsException(NONCE_NOT_FOUND);
        }

        CredentialsWriteEntity writeEntity = redisService.get(redisKey, CredentialsWriteEntity.class);

        if (writeEntity == null) {
            throw new CredentialsException(NONCE_ERROR);
        }
        if (!writeEntity.getUserId().equals(userId)) {
            throw new CredentialsException(NONCE_ERROR);
        }
        if (!writeEntity.getDeviceId().equals(deviceId)) {
            throw new CredentialsException(NONCE_ERROR);
        }
        if (!writeEntity.getOperation().equals(req.getOperation())) {
            throw new CredentialsException(NONCE_ERROR);
        }
        if (!Objects.equals(writeEntity.getCredentialsId(), credentialsId)) {
            throw new CredentialsException(NONCE_ERROR);
        }

        try {
            PublicKey publicKey = signatureService.getPublicKey(userId);
            CredentialsWritePayload payload =
                    new CredentialsWritePayload(
                            req.getWebsiteBytes(),
                            req.getUsernameBytes(),
                            req.getPasswordBytes(),
                            req.getIvWebsiteBytes(),
                            req.getIvUsernameBytes(),
                            req.getIvPasswordBytes(),
                            req.getNonce(),
                            req.getOperation(),
                            credentialsId
                    );
            byte[] payloadBytes = objectMapper.writeValueAsBytes(payload);
            boolean verified = signatureService.verifySignature(publicKey, payloadBytes, signature);
            if (!verified) {
                throw new CredentialsException(INVALID_SIGNATURE);
            }
            redisService.delete(redisKey);
        } catch (Exception e) {
            throw new CredentialsException(INVALID_SIGNATURE);
        }
    }

}
