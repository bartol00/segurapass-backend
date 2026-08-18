package com.security.passwordmanager.service;

import com.security.passwordmanager.exceptions.PasswordChangeException;
import com.security.passwordmanager.helpers.SrpFlow;
import com.security.passwordmanager.model.audit.AuditAction;
import com.security.passwordmanager.model.audit.AuditLogDao;
import com.security.passwordmanager.model.audit.AuditLogEntity;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.SrpRedisEntity;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import xyz.segurapass.api.password.*;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

import static com.security.passwordmanager.exceptions.enums.ErrorEnum.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordChangeService {

    private final UserDao userDao;
    private final AuditLogDao auditLogDao;

    private final RedisService redisService;
    private final SrpFlow srpFlow;

    @Transactional
    public ResponseEntity<PasswordChangeStartResp> startPasswordChange(UUID userId, PasswordChangeStartReq req) {
        UserEntity userEntity = userDao.findByUserId(userId);
        if (userEntity == null) {
            throw new PasswordChangeException(USER_NOT_EXISTS);
        }

        String userIdString = userEntity.getUserId().toString();
        String deviceIdString = req.getDeviceId().toString();
        String redisKey = RedisKeys.passwordChange(userIdString, deviceIdString);
        SrpRedisEntity srpRedisEntity = srpFlow.beginFlow(req.getA(), userEntity);
        redisService.save(
                redisKey,
                srpRedisEntity,
                Duration.of(10, ChronoUnit.SECONDS)
        );

        PasswordChangeStartResp resp = new PasswordChangeStartResp(
                srpRedisEntity.getB(),
                userEntity.getSaltAuthBytes()
        );

        log.info("Start Password Change for user: {} - Service", userId);

        return ResponseEntity.ok(resp);
    }

    @Transactional
    public ResponseEntity<Void> completePasswordChange(UUID userId, PasswordChangeCompleteReq req) {
        UserEntity userEntity = userDao.findByUserId(userId);
        if (userEntity == null) {
            throw new PasswordChangeException(USER_NOT_EXISTS);
        }

        String userIdString = userEntity.getUserId().toString();
        String deviceIdString = req.getDeviceId().toString();
        String redisKey = RedisKeys.passwordChange(userIdString, deviceIdString);
        if (!redisService.exists(redisKey)) {
            throw new PasswordChangeException(TOKEN_NOT_FOUND);
        }

        SrpRedisEntity srpRedisEntity = redisService.get(redisKey, SrpRedisEntity.class);
        redisService.delete(redisKey);

        BigInteger M1Server = srpFlow.calculateM1Server(srpRedisEntity);
        BigInteger M1Client = new BigInteger(1, Base64.getDecoder().decode(req.getM1()));

        if (!M1Server.equals(M1Client)) {
            throw new PasswordChangeException(SRP_VERIFICATION_FAILED);
        }

        userEntity.setSaltAuthBytes(req.getNewSaltAuth());
        userEntity.setVerifier(req.getNewVerifier());
        userEntity.setVaultKeyBytes(req.getNewVaultKey());
        userEntity.setIvVaultKeyBytes(req.getNewIvVaultKey());
        userEntity.setSaltKeyBytes(req.getNewSaltKey());
        userEntity.setSaltHkdfBytes(req.getNewSaltHkdf());
        userEntity.setPrivateSigningKeyBytes(req.getNewPrivateSigningKey());
        userEntity.setIvPrivateSigningKeyBytes(req.getNewIvPrivateSigningKey());
        userEntity = userDao.save(userEntity);

        AuditLogEntity auditLogEntity = new AuditLogEntity();
        auditLogEntity.setUserId(userEntity.getUserId());
        auditLogEntity.setTimestamp(Instant.now());
        auditLogEntity.setAction(AuditAction.PASSWORD_CHANGED);
        auditLogEntity.setIpAddress(MDC.get("clientIp"));
        auditLogEntity.setSuccess(true);
        auditLogDao.save(auditLogEntity);

        log.info("Complete Password Change for user: {} - Service", userId);

        return ResponseEntity.ok(null);
    }

}
