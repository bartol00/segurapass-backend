package com.security.passwordmanager.service;

import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.SessionRedisEntity;
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
    private final SrpDao srpDao;
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

        String verificationToken = tokenGenerator.generateEmailVerifier();
        String tokenHash = tokenHasher.generateSha256(verificationToken);
        UserRedisEntity userRedisEntity = new UserRedisEntity(
                UUID.randomUUID(),
                req.getEmail(),
                req.getSaltAuth(),
                req.getVerifier(),
                req.getSaltKey(),
                Instant.now()
        );
        redisService.save(
                "segurapass:email_unverified:" + tokenHash,
                userRedisEntity,
                Duration.of(15, ChronoUnit.MINUTES)
        );

        emailService.sendVerificationEmail(req.getEmail(), verificationToken);

        log.info("Register User for user {} - Service", tokenHasher.generateSha256Email(req.getEmail()));

        return ResponseEntity.ok(null);
    }

    @Transactional
    public ResponseEntity<LoginStartResp> loginUserStart(LoginStartReq req) {
        if (!userDao.existsByEmail(req.getEmail())) {
            throw new AuthorizationException(USER_NOT_EXISTS);
        }

        UserEntity userEntity = userDao.findByEmail(req.getEmail());
        if (!userEntity.getEmailVerified()) {
            throw new AuthorizationException(USER_EMAIL_UNVERIFIED);
        }

        log.info("Login Start for user {} - Service", tokenHasher.generateSha256Email(userEntity.getEmail()));

        SrpEntity srpEntity = srpFlow.beginFlow(req.getA(), req.getDeviceId(), userEntity);

        SrpEntity existing = srpDao.findByUserEntity_EmailAndDeviceId(req.getEmail(), req.getDeviceId());
        if (existing != null) {
            srpDao.delete(existing);
        }
        srpDao.save(srpEntity);

        LoginStartResp resp = new LoginStartResp();
        resp.setSaltAuth(userEntity.getSaltAuth());
        resp.setB(srpEntity.getB());

        return ResponseEntity.ok(resp);
    }

    @Transactional
    public ResponseEntity<LoginCompleteResp> loginUserEnd(LoginCompleteReq req) {
        SrpEntity srpEntity = srpDao.findByUserEntity_EmailAndDeviceId(req.getEmail(), req.getDeviceId());
        if (srpEntity == null) {
            throw new AuthorizationException(SRP_SESSION_NOT_FOUND);
        }

        srpDao.delete(srpEntity);

        if (srpEntity.getExpiryTime().isBefore(Instant.now())) {
            throw new AuthorizationException(SRP_SESSION_EXPIRED);
        }

        BigInteger M1Server = srpFlow.calculateM1Server(srpEntity);
        BigInteger M1Client = new BigInteger(1, Base64.getDecoder().decode(req.getM1()));

        if (!M1Server.equals(M1Client)) {
            throw new AuthorizationException(SRP_VERIFICATION_FAILED);
        }

        log.info("Login Complete for user {} - Service", tokenHasher.generateSha256Email(srpEntity.getUserEntity().getEmail()));

        BigInteger M2Server = srpFlow.calculateM2Server(srpEntity, M1Client);

        UserEntity user = userDao.findByEmail(req.getEmail());
        user.setLastLogin(Instant.now());
        userDao.save(user);

        String refreshToken = tokenGenerator.generateRefreshToken(32);
        Instant refreshExpiry = Instant.now().plus(30, ChronoUnit.MINUTES);

        String tokenHash = tokenHasher.generateSha256(refreshToken);
        SessionRedisEntity sessionRedisEntity = new SessionRedisEntity(
                user.getUserId(),
                req.getDeviceId()
        );
        redisService.save(
                "segurapass:session:" + tokenHash,
                sessionRedisEntity,
                Duration.of(30, ChronoUnit.MINUTES)
        );

        AuditLogEntity auditLogEntity = new AuditLogEntity();
        auditLogEntity.setUserId(user.getUserId());
        auditLogEntity.setTimestamp(Instant.now());
        auditLogEntity.setAction(AuditAction.LOGIN_SUCCESS);
        auditLogEntity.setIpAddress(MDC.get("clientIp"));
        auditLogEntity.setSuccess(true);
        auditLogDao.save(auditLogEntity);

        LoginCompleteResp resp = new LoginCompleteResp();
        resp.setM2(Base64.getEncoder().encodeToString(M2Server.toByteArray()));
        resp.setSaltKey(user.getSaltKey());
        resp.setAccessToken(generateJwt(user.getUserId(), req.getDeviceId()));
        resp.setRefreshToken(refreshToken);
        resp.setRefreshTokenExpiryTime(refreshExpiry);

        return ResponseEntity.ok(resp);
    }

    public ResponseEntity<RefreshResp> refreshJWT(RefreshReq req) {
        String tokenHash = tokenHasher.generateSha256(req.getRefreshToken());
        String redisKey = "segurapass:session:" + tokenHash;
        if (!redisService.exists(redisKey)) {
            throw new AuthorizationException(TOKEN_EXPIRED);
        }

        SessionRedisEntity sessionRedisEntity = redisService.get(redisKey, SessionRedisEntity.class);
        UserEntity userEntity = userDao.findByUserId(sessionRedisEntity.getUserId());

        log.info("JWT Refresh for user {} - Service", sessionRedisEntity.getUserId());

        RefreshResp resp = new RefreshResp();
        resp.setAccessToken(generateJwt(userEntity.getUserId(), sessionRedisEntity.getDeviceId()));

        return ResponseEntity.ok(resp);
    }

    @Transactional
    public ResponseEntity<Void> logout(RefreshReq req) {
        String tokenHash = tokenHasher.generateSha256(req.getRefreshToken());
        String redisKey = "segurapass:session:" + tokenHash;
        if (!redisService.exists(redisKey)) {
            throw new AuthorizationException(TOKEN_EXPIRED);
        }

        SessionRedisEntity sessionRedisEntity = redisService.get(redisKey, SessionRedisEntity.class);

        redisService.delete(redisKey);

        log.info("Logout for user {} - Service", sessionRedisEntity.getUserId());

        return ResponseEntity.ok(null);
    }

    @Transactional
    public ResponseEntity<String> verifyEmail(String token) {
        String tokenHash = tokenHasher.generateSha256(token);
        String redisKey = "segurapass:email_unverified:" + tokenHash;
        if (!redisService.exists(redisKey)) {
            throw new AuthorizationException(USER_VERIFICATION_NOT_EXISTS);
        }

        UserRedisEntity userRedisEntity = redisService.get(redisKey, UserRedisEntity.class);
        redisService.delete(redisKey);

        if (userDao.existsByEmail(userRedisEntity.getEmail())) {
            throw new AuthorizationException(USER_EXISTS);
        }

        UserEntity userEntity = new UserEntity();
        userEntity.setUserId(userRedisEntity.getUserId());
        userEntity.setEmail(userRedisEntity.getEmail());
        userEntity.setSaltAuth(userRedisEntity.getSaltAuth());
        userEntity.setVerifier(userRedisEntity.getVerifier());
        userEntity.setSaltKey(userRedisEntity.getSaltKey());
        userEntity.setEmailVerified(true);
        userEntity.setCreationTime(userRedisEntity.getCreationTime());
        userEntity.setLastLogin(Instant.now());
        userDao.save(userEntity);

        log.info("Email Verification for user {} - Service", tokenHasher.generateSha256Email(userEntity.getEmail()));

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

}
