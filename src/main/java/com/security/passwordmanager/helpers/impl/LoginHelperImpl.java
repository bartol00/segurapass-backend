package com.security.passwordmanager.helpers.impl;

import com.security.passwordmanager.config.JwtService;
import com.security.passwordmanager.helpers.LoginHelper;
import com.security.passwordmanager.helpers.TokenGenerator;
import com.security.passwordmanager.helpers.TokenHasher;
import com.security.passwordmanager.model.audit.AuditAction;
import com.security.passwordmanager.model.audit.AuditLogDao;
import com.security.passwordmanager.model.audit.AuditLogEntity;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.mfa.TotpEntity;
import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.SessionRedisEntity;
import com.security.passwordmanager.redis.entities.TotpLoginEntity;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import xyz.segurapass.api.authorization.LoginCompleteReq;
import xyz.segurapass.api.authorization.LoginCompleteResp;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

@Service
@Slf4j
public class LoginHelperImpl implements LoginHelper {

    @Autowired
    private UserDao userDao;
    @Autowired
    private AuditLogDao auditLogDao;
    @Autowired
    private RedisService redisService;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private TokenGenerator tokenGenerator;
    @Autowired
    private TokenHasher tokenHasher;

    @Override
    public LoginCompleteResp generateLoginCompleteResp(UUID userId, UUID deviceId) {
        UserEntity userEntity = userDao.findByUserId(userId);
        userEntity.setLastLogin(Instant.now());
        userDao.save(userEntity);

        String refreshToken = tokenGenerator.generateRefreshToken(32);
        Instant refreshExpiry = Instant.now().plus(30, ChronoUnit.MINUTES);

        String tokenHash = tokenHasher.generateSha256(refreshToken);
        SessionRedisEntity sessionRedisEntity = new SessionRedisEntity(
                userId,
                deviceId
        );
        redisService.save(
                RedisKeys.session(tokenHash),
                sessionRedisEntity,
                Duration.between(Instant.now(), refreshExpiry)
        );

        AuditLogEntity auditLogEntity = new AuditLogEntity();
        auditLogEntity.setUserId(userEntity.getUserId());
        auditLogEntity.setTimestamp(Instant.now());
        auditLogEntity.setAction(AuditAction.LOGIN_SUCCESS);
        auditLogEntity.setIpAddress(MDC.get("clientIp"));
        auditLogEntity.setSuccess(true);
        auditLogDao.save(auditLogEntity);

        LoginCompleteResp resp = new LoginCompleteResp(
                null,
                userEntity.getVaultKeyBytes(),
                userEntity.getIvVaultKeyBytes(),
                userEntity.getSaltKeyBytes(),
                userEntity.getSaltHkdfBytes(),
                userEntity.getPrivateSigningKeyBytes(),
                userEntity.getPublicSigningKeyBytes(),
                userEntity.getIvPrivateSigningKeyBytes(),
                jwtService.generateJwt(userId, deviceId),
                refreshToken,
                refreshExpiry
        );

        log.info("Complete Login for user {}", userEntity.getUserId());

        return resp;
    }

    @Override
    public LoginCompleteResp generateMfaLoginResp(
            UserEntity userEntity,
            LoginCompleteReq req,
            BigInteger M2Server
    ) {
        String totpCode = tokenGenerator.generateRandomToken(32);
        String redisKey = RedisKeys.totpLogin(tokenHasher.generateSha256(totpCode));

        TotpEntity totpEntity = userEntity.getTotpEntity();
        TotpLoginEntity totpLoginEntity = new TotpLoginEntity(
                userEntity.getUserId(),
                req.getDeviceId(),
                totpEntity.getTotpTokenBytes(),
                totpEntity.getTotpTokenIv()
        );

        redisService.save(redisKey, totpLoginEntity, Duration.of(10, ChronoUnit.MINUTES));

        return new LoginCompleteResp(
                Base64.getEncoder().encodeToString(M2Server.toByteArray()),
                totpCode
        );
    }

}
