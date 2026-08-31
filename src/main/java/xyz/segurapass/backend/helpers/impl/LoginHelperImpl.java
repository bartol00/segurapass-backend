package xyz.segurapass.backend.helpers.impl;

import xyz.segurapass.backend.config.JwtService;
import xyz.segurapass.backend.helpers.LoginHelper;
import xyz.segurapass.backend.helpers.TokenGenerator;
import xyz.segurapass.backend.helpers.TokenHasher;
import xyz.segurapass.backend.model.audit.AuditAction;
import xyz.segurapass.backend.model.audit.AuditLogDao;
import xyz.segurapass.backend.model.audit.AuditLogEntity;
import xyz.segurapass.backend.model.authorization.UserDao;
import xyz.segurapass.backend.model.authorization.UserEntity;
import xyz.segurapass.backend.model.mfa.TotpEntity;
import xyz.segurapass.backend.redis.RedisKeys;
import xyz.segurapass.backend.redis.RedisService;
import xyz.segurapass.backend.redis.entities.SessionRedisEntity;
import xyz.segurapass.backend.redis.entities.TotpLoginEntity;
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

        log.info("Login Complete for user {}", userEntity.getUserId());

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

        log.info("Generated TOTP code for user {}", userEntity.getUserId());

        return new LoginCompleteResp(
                Base64.getEncoder().encodeToString(M2Server.toByteArray()),
                totpCode
        );
    }

}
