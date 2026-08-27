package com.security.passwordmanager.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.passwordmanager.helpers.NonceHelper;
import com.security.passwordmanager.helpers.SignatureService;
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
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import static com.security.passwordmanager.exceptions.enums.ErrorEnum.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialsService {

    private final CredentialMapper mapper;

    private final RedisService redisService;
    private final SignatureService signatureService;
    private final NonceHelper nonceHelper;

    private final CredentialsDao credentialsDao;
    private final UserDao userDao;
    private final AuditLogDao auditLogDao;
    private final ObjectMapper objectMapper;

    @SuppressWarnings("FieldCanBeLocal")
    private final int MAX_REQUEST_BYTES_LEN = 1024;
    @SuppressWarnings("FieldCanBeLocal")
    private final int IV_BYTES_LEN = 12;

    @Transactional
    public ResponseEntity<Page<CredentialsResp>> getCredentials(UUID userId, int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<CredentialsEntity> credentialsEntityPage = credentialsDao.findByUserEntity_UserId(userId, pageable);

        log.info("Get Credentials");

        return ResponseEntity.ok(mapper.toCredentialsRespPage(credentialsEntityPage));
    }

    @Transactional
    public ResponseEntity<CredentialsResp> getCredentialById(UUID id, UUID userId) {
        CredentialsEntity credentialsEntity = credentialsDao.findByCredentialsIdAndUserEntity_UserId(id, userId);
        if (credentialsEntity == null) {
            throw new CredentialsException(CREDENTIAL_NOT_EXISTS);
        }

        log.info("Get Credential By ID {}", id);

        return ResponseEntity.ok(mapper.toCredentialsResp(credentialsEntity));
    }

    public ResponseEntity<NonceResp> createCredentialsStart(UUID userId, UUID deviceId) {
        String nonce = generateCredentialsNonce(userId, deviceId, CredentialsOperation.CREATE, null);
        log.info("Start Credential Create");
        return ResponseEntity.ok(new NonceResp(nonce));
    }

    @Transactional
    public ResponseEntity<CredentialsResp> createCredentialsEnd(
            CredentialsReq req,
            UUID userId,
            UUID deviceId,
            String signature
    ) {
        validateCredentialsReq(req);
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

        log.info("Complete Credentials Create");

        return ResponseEntity.ok(mapper.toCredentialsResp(credentialsEntity));
    }

    public ResponseEntity<NonceResp> updateCredentialsStart(UUID credentialsId, UUID userId, UUID deviceId) {
        String nonce = generateCredentialsNonce(userId, deviceId, CredentialsOperation.UPDATE, credentialsId);
        log.info("Start Credential Update");
        return ResponseEntity.ok(new NonceResp(nonce));
    }

    @Transactional
    public ResponseEntity<CredentialsResp> updateCredentialsEnd(
            UUID id,
            CredentialsReq req,
            UUID userId,
            UUID deviceId,
            String signature
    ) {
        validateCredentialsReq(req);
        verifyNonceAndSignature(id, userId, deviceId, req, signature);

        CredentialsEntity entity = credentialsDao.findByCredentialsIdAndUserEntity_UserId(id, userId);
        if (entity == null) {
            log.warn("Credential with ID {} does not exist - Credential Update", id);
            throw new CredentialsException(CREDENTIAL_NOT_EXISTS);
        }

        if (req.getWebsiteBytes() != null) {
            if (req.getIvWebsiteBytes() == null) {
                log.warn("Credential has website bytes but is missing IV");
                throw new CredentialsException(CREDENTIAL_UPDATE_IV_MISSING);
            }
            entity.setWebsiteBytes(req.getWebsiteBytes());
            entity.setIvWebsiteBytes(req.getIvWebsiteBytes());
        }
        if (req.getUsernameBytes() != null) {
            if (req.getIvUsernameBytes() == null) {
                log.warn("Credential has username bytes but is missing IV");
                throw new CredentialsException(CREDENTIAL_UPDATE_IV_MISSING);
            }
            entity.setUsernameBytes(req.getUsernameBytes());
            entity.setIvUsernameBytes(req.getIvUsernameBytes());
        }
        if (req.getPasswordBytes() != null) {
            if (req.getIvPasswordBytes() == null) {
                log.warn("Credential has password bytes but is missing IV");
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

        log.info("Complete Credentials Update");

        return ResponseEntity.ok(mapper.toCredentialsResp(entity));
    }

    public ResponseEntity<NonceResp> deleteCredentialsStart(UUID credentialsId, UUID userId, UUID deviceId) {
        String nonce = generateCredentialsNonce(userId, deviceId, CredentialsOperation.DELETE, credentialsId);
        log.info("Start Credential Delete");
        return ResponseEntity.ok(new NonceResp(nonce));
    }

    @Transactional
    public ResponseEntity<Void> deleteCredentialsEnd(
            UUID id,
            CredentialsReq req,
            UUID userId,
            UUID deviceId,
            String signature
    ) {
        verifyNonceAndSignature(id, userId, deviceId, req, signature);

        CredentialsEntity credentialsEntity = credentialsDao.findByCredentialsIdAndUserEntity_UserId(id, userId);
        if (credentialsEntity == null) {
            log.warn("Credential with ID {} does not exist - Credential Delete", id);
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

        log.info("Complete Credentials Delete");

        return ResponseEntity.ok(null);
    }

    private String generateCredentialsNonce(
            UUID userId,
            UUID deviceId,
            CredentialsOperation operation,
            UUID credentialsId
    ) {
        CredentialsWriteEntity writeEntity = new CredentialsWriteEntity(
                userId,
                deviceId,
                operation,
                credentialsId
        );
        return nonceHelper.generateNonce(writeEntity, RedisKeys::credentialsNonce);
    }

    private void validateCredentialsReq(CredentialsReq req) {
        if ((req.getWebsiteBytes() != null && req.getWebsiteBytes().length > MAX_REQUEST_BYTES_LEN)
        || (req.getUsernameBytes() != null && req.getUsernameBytes().length > MAX_REQUEST_BYTES_LEN)
        || (req.getPasswordBytes() != null && req.getPasswordBytes().length > MAX_REQUEST_BYTES_LEN)) {
            log.warn("Credentials request bytes are longer than {} bytes", MAX_REQUEST_BYTES_LEN);
            throw new CredentialsException(CREDENTIAL_REQ_BYTES_TOO_LONG);
        }

        if ((req.getIvWebsiteBytes() != null && req.getIvWebsiteBytes().length != IV_BYTES_LEN)
        || (req.getIvUsernameBytes() != null && req.getIvUsernameBytes().length != IV_BYTES_LEN)
        || (req.getIvPasswordBytes() != null && req.getIvPasswordBytes().length != IV_BYTES_LEN)) {
            log.warn("Credentials IV bytes is not exactly {} bytes long", IV_BYTES_LEN);
            throw new CredentialsException(CREDENTIAL_REQ_IV_BYTES_LEN_ERROR);
        }
    }

    private void verifyNonceAndSignature(
            UUID credentialsId,
            UUID userId,
            UUID deviceId,
            CredentialsReq req,
            String signature
    ) {
        if (req.getNonce() == null || req.getNonce().isEmpty()) {
            log.warn("Credentials nonce is null or empty");
            throw new CredentialsException(CREDENTIAL_NONCE_MISSING);
        }

        String redisKey = RedisKeys.credentialsNonce(req.getNonce());
        if (!redisService.exists(redisKey)) {
            log.warn("Credentials nonce could not be found {}", redisKey);
            throw new CredentialsException(NONCE_NOT_FOUND);
        }

        CredentialsWriteEntity writeEntity = redisService.get(redisKey, CredentialsWriteEntity.class);

        if (writeEntity == null) {
            log.warn("Write entity is null");
            throw new CredentialsException(NONCE_ERROR);
        }
        if (!writeEntity.getUserId().equals(userId)) {
            log.warn("Write entity user ID mismatch");
            throw new CredentialsException(NONCE_ERROR);
        }
        if (!writeEntity.getDeviceId().equals(deviceId)) {
            log.warn("Write entity device ID mismatch");
            throw new CredentialsException(NONCE_ERROR);
        }
        if (!writeEntity.getOperation().equals(req.getOperation())) {
            log.warn("Write entity operation mismatch");
            throw new CredentialsException(NONCE_ERROR);
        }
        if (!Objects.equals(writeEntity.getCredentialsId(), credentialsId)) {
            log.warn("Write entity credentials ID mismatch");
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
                log.warn("Signature could not be verified");
                throw new CredentialsException(INVALID_SIGNATURE);
            }
            redisService.delete(redisKey);
        } catch (Exception e) {
            log.warn("Exception occurred during signature verification", e);
            throw new CredentialsException(INVALID_SIGNATURE);
        }
    }

}
