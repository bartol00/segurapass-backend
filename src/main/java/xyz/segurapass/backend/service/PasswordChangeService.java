package xyz.segurapass.backend.service;

import xyz.segurapass.backend.exceptions.PasswordChangeException;
import xyz.segurapass.backend.helpers.SrpFlow;
import xyz.segurapass.backend.model.audit.AuditAction;
import xyz.segurapass.backend.model.audit.AuditLogDao;
import xyz.segurapass.backend.model.audit.AuditLogEntity;
import xyz.segurapass.backend.model.authorization.UserDao;
import xyz.segurapass.backend.model.authorization.UserEntity;
import xyz.segurapass.backend.redis.RedisKeys;
import xyz.segurapass.backend.redis.RedisService;
import xyz.segurapass.backend.redis.entities.SrpRedisEntity;
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

import static xyz.segurapass.backend.exceptions.enums.ErrorEnum.*;

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
            log.warn("User does not exist - Password Change Start");
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

        log.info("Start Password Change");

        return ResponseEntity.ok(resp);
    }

    @Transactional
    public ResponseEntity<Void> completePasswordChange(UUID userId, PasswordChangeCompleteReq req) {
        UserEntity userEntity = userDao.findByUserId(userId);
        if (userEntity == null) {
            log.warn("User does not exist - Password Change Complete");
            throw new PasswordChangeException(USER_NOT_EXISTS);
        }

        String userIdString = userEntity.getUserId().toString();
        String deviceIdString = req.getDeviceId().toString();
        String redisKey = RedisKeys.passwordChange(userIdString, deviceIdString);
        if (!redisService.exists(redisKey)) {
            log.warn("Token does not exist {} - Password Change Complete", redisKey);
            throw new PasswordChangeException(TOKEN_NOT_FOUND);
        }

        SrpRedisEntity srpRedisEntity = redisService.get(redisKey, SrpRedisEntity.class);
        redisService.delete(redisKey);

        BigInteger M1Server = srpFlow.calculateM1Server(srpRedisEntity);
        BigInteger M1Client = new BigInteger(1, Base64.getDecoder().decode(req.getM1()));

        if (!M1Server.equals(M1Client)) {
            log.warn("M1 could not be verified - Password Change Complete");
            throw new PasswordChangeException(PASSWORD_INCORRECT);
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

        log.info("Complete Password Change");

        return ResponseEntity.ok(null);
    }

}
