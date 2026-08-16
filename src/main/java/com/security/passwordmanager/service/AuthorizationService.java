package com.security.passwordmanager.service;

import com.security.passwordmanager.config.JwtService;
import com.security.passwordmanager.model.mfa.TotpEntity;
import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.SessionRedisEntity;
import com.security.passwordmanager.redis.entities.SrpRedisEntity;
import com.security.passwordmanager.redis.entities.TotpLoginEntity;
import com.security.passwordmanager.redis.entities.UserRedisEntity;
import xyz.segurapass.api.authorization.*;
import com.security.passwordmanager.exceptions.AuthorizationException;
import com.security.passwordmanager.helpers.EmailService;
import com.security.passwordmanager.helpers.SrpFlow;
import com.security.passwordmanager.helpers.TokenGenerator;
import com.security.passwordmanager.helpers.TokenHasher;
import com.security.passwordmanager.model.audit.AuditAction;
import com.security.passwordmanager.model.audit.AuditLogDao;
import com.security.passwordmanager.model.audit.AuditLogEntity;
import com.security.passwordmanager.model.authorization.*;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.regex.Pattern;

import static com.security.passwordmanager.exceptions.ErrorEnum.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthorizationService {

    private final JwtService jwtService;
    private final UserDao userDao;
    private final AuditLogDao auditLogDao;
    private final EmailService emailService;
    private final RedisService redisService;
    private final SrpFlow srpFlow;
    private final TokenGenerator tokenGenerator;
    private final TokenHasher tokenHasher;

    private static final String EMAIL_REGEX =
            "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
    private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);
    private static final Set<String> ALLOWED_DOMAINS = Set.of(
            "gmail.com",
            "outlook.com",
            "hotmail.com",
            "yahoo.com",
            "proton.me",
            "icloud.com",
            "aol.com",
            "zoho.com"
    );

    @Transactional
    public ResponseEntity<Void> registerUser(RegistrationReq req) {
        if (!isValidEmail(req.getEmail())) {
            throw new AuthorizationException(USER_EMAIL_INVALID);
        }
        if (userDao.existsByEmail(req.getEmail())) {
            throw new AuthorizationException(USER_EXISTS);
        }

        String emailHash = tokenHasher.generateSha256Email(req.getEmail());
        String redisEmailKey = RedisKeys.emailUnverifiedEmail(emailHash);
        if (redisService.exists(redisEmailKey)) {
            throw new AuthorizationException(EMAIL_PENDING_VERIFICATION);
        }

        String verificationToken = tokenGenerator.generateRandomToken(32);
        String tokenHash = tokenHasher.generateSha256(verificationToken);
        UserRedisEntity userRedisEntity = new UserRedisEntity(
                UUID.randomUUID(),
                req.getEmail(),
                req.getSaltAuth(),
                req.getVerifier(),
                req.getVaultKey(),
                req.getIvVaultKey(),
                req.getSaltKey(),
                req.getSaltHkdf(),
                req.getPrivateSigningKey(),
                req.getPublicSigningKey(),
                req.getIvPrivateSigningKey(),
                Instant.now()
        );

        Instant in15Minutes = Instant.now().plus(15, ChronoUnit.MINUTES);
        redisService.save(
                RedisKeys.emailUnverified(tokenHash),
                userRedisEntity,
                Duration.between(Instant.now(), in15Minutes)
        );
        redisService.save(
                redisEmailKey,
                null,
                Duration.between(Instant.now(), in15Minutes)
        );

        emailService.sendVerificationEmail(req.getEmail(), verificationToken);

        log.info("Register User for user (email hash): {} - Service", emailHash);

        return ResponseEntity.ok(null);
    }

    @Transactional
    public ResponseEntity<LoginStartResp> loginUserStart(LoginStartReq req) {
        UserEntity userEntity = userDao.findByEmail(req.getEmail());
        if (userEntity == null) {
            throw new AuthorizationException(USER_NOT_EXISTS);
        }

        String userIdString = userEntity.getUserId().toString();
        String deviceIdString = req.getDeviceId().toString();
        String redisKey = RedisKeys.srp(userIdString, deviceIdString);
        SrpRedisEntity srpRedisEntity = srpFlow.beginFlow(req.getA(), userEntity);
        redisService.save(
                redisKey,
                srpRedisEntity,
                Duration.of(10, ChronoUnit.SECONDS)
        );

        LoginStartResp resp = new LoginStartResp(
                srpRedisEntity.getB(),
                userEntity.getSaltAuthBytes()
        );

        log.info("Login Start for user (email hash): {} - Service", tokenHasher.generateSha256Email(userEntity.getEmail()));

        return ResponseEntity.ok(resp);
    }

    @Transactional
    public ResponseEntity<LoginCompleteResp> loginUserEnd(LoginCompleteReq req) {
        UserEntity userEntity = userDao.findByEmail(req.getEmail());
        if (userEntity == null) {
            throw new AuthorizationException(USER_NOT_EXISTS);
        }

        String userIdString = userEntity.getUserId().toString();
        String deviceIdString = req.getDeviceId().toString();
        String redisKey = RedisKeys.srp(userIdString, deviceIdString);
        if (!redisService.exists(redisKey)) {
            throw new AuthorizationException(TOKEN_NOT_FOUND);
        }

        SrpRedisEntity srpRedisEntity = redisService.get(redisKey, SrpRedisEntity.class);
        redisService.delete(redisKey);

        BigInteger M1Server = srpFlow.calculateM1Server(srpRedisEntity);
        BigInteger M1Client = new BigInteger(1, Base64.getDecoder().decode(req.getM1()));

        if (!M1Server.equals(M1Client)) {
            throw new AuthorizationException(SRP_VERIFICATION_FAILED);
        }

        BigInteger M2Server = srpFlow.calculateM2Server(srpRedisEntity, M1Client);

        LoginCompleteResp resp;
        if (userEntity.getTotpEnabled() == null || !userEntity.getTotpEnabled()) {
            resp = generateRespWithoutMfa(userEntity, req, M2Server);
        } else {
            resp = generateRespWithMfa(userEntity, req, M2Server);
        }

        return ResponseEntity.ok(resp);
    }

    public ResponseEntity<RefreshResp> refreshJWT(RefreshReq req) {
        String tokenHash = tokenHasher.generateSha256(req.getRefreshToken());
        String redisKey = RedisKeys.session(tokenHash);
        if (!redisService.exists(redisKey)) {
            throw new AuthorizationException(TOKEN_NOT_FOUND);
        }

        SessionRedisEntity sessionRedisEntity = redisService.get(redisKey, SessionRedisEntity.class);
        UserEntity userEntity = userDao.findByUserId(sessionRedisEntity.getUserId());

        RefreshResp resp = new RefreshResp();
        resp.setAccessToken(generateJwt(userEntity.getUserId(), sessionRedisEntity.getDeviceId()));

        log.info("JWT Refresh for user: {} - Service", sessionRedisEntity.getUserId());

        return ResponseEntity.ok(resp);
    }

    public ResponseEntity<Void> logout(RefreshReq req) {
        String tokenHash = tokenHasher.generateSha256(req.getRefreshToken());
        String redisKey = RedisKeys.session(tokenHash);
        if (!redisService.exists(redisKey)) {
            throw new AuthorizationException(TOKEN_NOT_FOUND);
        }

        SessionRedisEntity sessionRedisEntity = redisService.get(redisKey, SessionRedisEntity.class);

        redisService.delete(redisKey);

        log.info("Logout for user: {} - Service", sessionRedisEntity.getUserId());

        return ResponseEntity.ok(null);
    }

    @Transactional
    public ResponseEntity<String> verifyEmail(String token) {
        String tokenHash = tokenHasher.generateSha256(token);
        String redisKey = RedisKeys.emailUnverified(tokenHash);
        if (!redisService.exists(redisKey)) {
            throw new AuthorizationException(USER_VERIFICATION_NOT_EXISTS);
        }

        UserRedisEntity userRedisEntity = redisService.get(redisKey, UserRedisEntity.class);
        redisService.delete(redisKey);

        String emailHash = tokenHasher.generateSha256Email(userRedisEntity.getEmail());
        String redisEmailKey = RedisKeys.emailUnverifiedEmail(emailHash);
        redisService.delete(redisEmailKey);

        UserEntity userEntity = new UserEntity();
        userEntity.setUserId(userRedisEntity.getUserId());
        userEntity.setEmail(userRedisEntity.getEmail());
        userEntity.setSaltAuthBytes(userRedisEntity.getSaltAuth());
        userEntity.setVerifier(userRedisEntity.getVerifier());
        userEntity.setVaultKeyBytes(userRedisEntity.getVaultKey());
        userEntity.setIvVaultKeyBytes(userRedisEntity.getIvVaultKey());
        userEntity.setSaltKeyBytes(userRedisEntity.getSaltKey());
        userEntity.setSaltHkdfBytes(userRedisEntity.getSaltHkdf());
        userEntity.setPrivateSigningKeyBytes(userRedisEntity.getPrivateSigningKey());
        userEntity.setPublicSigningKeyBytes(userRedisEntity.getPublicSigningKey());
        userEntity.setIvPrivateSigningKeyBytes(userRedisEntity.getIvPrivateSigningKey());
        userEntity.setCreationTime(userRedisEntity.getCreationTime());
        userEntity.setLastLogin(Instant.now());
        userDao.save(userEntity);

        log.info("Email Verification for user (email hash): {} - Service", emailHash);

        return ResponseEntity.ok("Email has been verified successfully");
    }

    private String generateJwt(UUID userId, UUID deviceId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("deviceId", deviceId);
        return jwtService.generateToken(userId.toString(), claims, 180);
    }

    private boolean isValidEmail(String email) {
        if (email == null || email.isBlank()) {
            return false;
        }

        if (!EMAIL_PATTERN.matcher(email).matches()) {
            return false;
        }

        String domain = email.substring(email.lastIndexOf('@') + 1).toLowerCase();
        return ALLOWED_DOMAINS.contains(domain);
    }

    private LoginCompleteResp generateRespWithoutMfa(
            UserEntity userEntity,
            LoginCompleteReq req,
            BigInteger M2Server
    ) {
        userEntity.setLastLogin(Instant.now());
        userDao.save(userEntity);

        String refreshToken = tokenGenerator.generateRefreshToken(32);
        Instant refreshExpiry = Instant.now().plus(30, ChronoUnit.MINUTES);

        String tokenHash = tokenHasher.generateSha256(refreshToken);
        SessionRedisEntity sessionRedisEntity = new SessionRedisEntity(
                userEntity.getUserId(),
                req.getDeviceId()
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
                Base64.getEncoder().encodeToString(M2Server.toByteArray()),
                userEntity.getVaultKeyBytes(),
                userEntity.getIvVaultKeyBytes(),
                userEntity.getSaltKeyBytes(),
                userEntity.getSaltHkdfBytes(),
                userEntity.getPrivateSigningKeyBytes(),
                userEntity.getPublicSigningKeyBytes(),
                userEntity.getIvPrivateSigningKeyBytes(),
                generateJwt(userEntity.getUserId(), req.getDeviceId()),
                refreshToken,
                refreshExpiry
        );

        log.info(
                "Login Complete for user (email hash): {} - Service",
                tokenHasher.generateSha256Email(userEntity.getEmail())
        );

        return resp;
    }

    private LoginCompleteResp generateRespWithMfa(
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
                totpEntity.getEncryptedToken(),
                totpEntity.getTokenIv()
        );

        redisService.save(redisKey, totpLoginEntity, Duration.of(10, ChronoUnit.MINUTES));

        return new LoginCompleteResp(
                Base64.getEncoder().encodeToString(M2Server.toByteArray()),
                totpCode
        );
    }

}
