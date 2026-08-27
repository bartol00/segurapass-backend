package com.security.passwordmanager.service;

import com.security.passwordmanager.config.EmailClient;
import com.security.passwordmanager.config.JwtService;
import com.security.passwordmanager.helpers.*;
import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.SessionRedisEntity;
import com.security.passwordmanager.redis.entities.SrpRedisEntity;
import com.security.passwordmanager.redis.entities.UserRedisEntity;
import xyz.segurapass.api.authorization.*;
import com.security.passwordmanager.exceptions.AuthorizationException;
import com.security.passwordmanager.model.authorization.*;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.regex.Pattern;

import static com.security.passwordmanager.exceptions.enums.ErrorEnum.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthorizationService {

    private final JwtService jwtService;
    private final UserDao userDao;
    private final EmailService emailService;
    private final RedisService redisService;
    private final EmailClient emailClient;
    private final SrpFlow srpFlow;
    private final TokenGenerator tokenGenerator;
    private final TokenHasher tokenHasher;
    private final LoginHelper loginHelper;

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
            log.warn("Email {} is not valid", req.getEmail());
            throw new AuthorizationException(USER_EMAIL_INVALID);
        }

        String emailHash = tokenHasher.generateSha256Email(req.getEmail());

        if (userDao.existsByEmail(req.getEmail())) {
            log.warn("Email {} already exists", emailHash);
            throw new AuthorizationException(USER_EXISTS);
        }

        UUID userId = UUID.randomUUID();
        UserRedisEntity userRedisEntity = new UserRedisEntity(
                userId,
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

        if (emailClient.isActive()) {

            String redisEmailKey = RedisKeys.emailUnverifiedEmail(emailHash);
            if (redisService.exists(redisEmailKey)) {
                log.warn("Email {} is still pending verification", emailHash);
                throw new AuthorizationException(EMAIL_PENDING_VERIFICATION);
            }

            String verificationToken = tokenGenerator.generateRandomToken(32);
            String tokenHash = tokenHasher.generateSha256(verificationToken);

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

            log.info("Registration verification email sent to {}", emailHash);

        } else {
            UserEntity userEntity = generateUserEntity(userRedisEntity);
            userDao.save(userEntity);
            log.info("User registered directly with email {}", emailHash);
        }

        log.info("Registered User {}", userId);

        return ResponseEntity.ok(null);
    }

    @Transactional
    public ResponseEntity<LoginStartResp> loginUserStart(LoginStartReq req) {
        UserEntity userEntity = userDao.findByEmail(req.getEmail());
        if (userEntity == null) {
            log.warn("User with email {} does not exist - Login Start", tokenHasher.generateSha256Email(req.getEmail()));
            throw new AuthorizationException(LOGIN_INFORMATION_INCORRECT);
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

        log.info("Start Login for user {}", userEntity.getUserId());

        return ResponseEntity.ok(resp);
    }

    @Transactional
    public ResponseEntity<LoginCompleteResp> loginUserEnd(LoginCompleteReq req) {
        UserEntity userEntity = userDao.findByEmail(req.getEmail());
        if (userEntity == null) {
            log.warn("User with email {} does not exist - Login Complete", tokenHasher.generateSha256Email(req.getEmail()));
            throw new AuthorizationException(LOGIN_INFORMATION_INCORRECT);
        }

        String userIdString = userEntity.getUserId().toString();
        String deviceIdString = req.getDeviceId().toString();
        String redisKey = RedisKeys.srp(userIdString, deviceIdString);
        if (!redisService.exists(redisKey)) {
            log.warn("Token key could not be found {} - Login Complete", redisKey);
            throw new AuthorizationException(LOGIN_INFORMATION_INCORRECT);
        }

        SrpRedisEntity srpRedisEntity = redisService.get(redisKey, SrpRedisEntity.class);
        redisService.delete(redisKey);

        BigInteger M1Server = srpFlow.calculateM1Server(srpRedisEntity);
        BigInteger M1Client = new BigInteger(1, Base64.getDecoder().decode(req.getM1()));

        if (!M1Server.equals(M1Client)) {
            log.warn("M1 could not be verified - Login Complete");
            throw new AuthorizationException(LOGIN_INFORMATION_INCORRECT);
        }

        BigInteger M2Server = srpFlow.calculateM2Server(srpRedisEntity, M1Client);

        LoginCompleteResp resp;
        if (userEntity.getTotpEnabled() == null || !userEntity.getTotpEnabled()) {
            resp = loginHelper.generateLoginCompleteResp(userEntity.getUserId(), req.getDeviceId());
            resp.setM2(Base64.getEncoder().encodeToString(M2Server.toByteArray()));
        } else {
            resp = loginHelper.generateMfaLoginResp(userEntity, req, M2Server);
        }

        return ResponseEntity.ok(resp);
    }

    public ResponseEntity<RefreshResp> refreshJWT(RefreshReq req) {
        String tokenHash = tokenHasher.generateSha256(req.getRefreshToken());
        String redisKey = RedisKeys.session(tokenHash);
        if (!redisService.exists(redisKey)) {
            log.warn("Refresh token could not be found {} - Refresh JWT", redisKey);
            throw new AuthorizationException(TOKEN_NOT_FOUND);
        }

        SessionRedisEntity sessionRedisEntity = redisService.get(redisKey, SessionRedisEntity.class);
        UserEntity userEntity = userDao.findByUserId(sessionRedisEntity.getUserId());

        RefreshResp resp = new RefreshResp();
        resp.setAccessToken(jwtService.generateJwt(userEntity.getUserId(), sessionRedisEntity.getDeviceId()));

        log.info("Refreshed JWT {}", redisKey);

        return ResponseEntity.ok(resp);
    }

    public ResponseEntity<Void> logout(RefreshReq req) {
        String tokenHash = tokenHasher.generateSha256(req.getRefreshToken());
        String redisKey = RedisKeys.session(tokenHash);
        if (!redisService.exists(redisKey)) {
            log.warn("Refresh token could not be found {} - Logout", redisKey);
            throw new AuthorizationException(TOKEN_NOT_FOUND);
        }

        SessionRedisEntity sessionRedisEntity = redisService.get(redisKey, SessionRedisEntity.class);

        redisService.delete(redisKey);

        log.info("Logged out user {}", sessionRedisEntity.getUserId());

        return ResponseEntity.ok(null);
    }

    @Transactional
    public ResponseEntity<String> verifyEmail(String token) {
        if (!emailClient.isActive()) {
            throw new AuthorizationException(EMAIL_VERIFICATION_OFF);
        }

        String tokenHash = tokenHasher.generateSha256(token);
        String redisKey = RedisKeys.emailUnverified(tokenHash);
        if (!redisService.exists(redisKey)) {
            log.warn("User verification token does not exist {} - Verify Email", redisKey);
            throw new AuthorizationException(USER_VERIFICATION_NOT_EXISTS);
        }

        UserRedisEntity userRedisEntity = redisService.get(redisKey, UserRedisEntity.class);
        redisService.delete(redisKey);

        String emailHash = tokenHasher.generateSha256Email(userRedisEntity.getEmail());
        String redisEmailKey = RedisKeys.emailUnverifiedEmail(emailHash);
        redisService.delete(redisEmailKey);

        UserEntity userEntity = generateUserEntity(userRedisEntity);
        userDao.save(userEntity);

        log.info("Verified Email for email {}", emailHash);

        return ResponseEntity.ok("Email has been verified successfully");
    }

    private UserEntity generateUserEntity(UserRedisEntity userRedisEntity) {
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
        return userEntity;
    }

    private boolean isValidEmail(String email) {
        if (!emailClient.isActive()) {
            return true;
        }

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
