package com.security.passwordmanager.service;

import com.security.passwordmanager.api.authorization.*;
import com.security.passwordmanager.api.error.ApiError;
import com.security.passwordmanager.api.error.ApiErrorEnum;
import com.security.passwordmanager.config.EmailService;
import com.security.passwordmanager.config.SrpFlow;
import com.security.passwordmanager.config.TokenGenerator;
import com.security.passwordmanager.config.TokenHasher;
import com.security.passwordmanager.mapper.UserMapper;
import com.security.passwordmanager.model.authorization.*;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class AuthorizationService {

    private final UserMapper userMapper;
    private final JwtService jwtService;
    private final UserDao userDao;
    private final SessionDao sessionDao;
    private final SrpDao srpDao;
    private final EmailService emailService;
    private final SrpFlow srpFlow;

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
    public ResponseEntity<?> registerUser(RegistrationReq req) {
        if (!isValidEmail(req.getEmail())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_EMAIL_INVALID);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }
        if (userDao.existsByEmail(req.getEmail())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        String verificationString = TokenGenerator.generateEmailVerifier();

        UserEntity userEntity = userMapper.toUserEntity(req);
        userEntity.setUserId(UUID.randomUUID());
        userEntity.setVerificationString(verificationString);
        userEntity.setVerificationExpiryTime(Instant.now().plus(15, ChronoUnit.MINUTES));
        userEntity.setEmailVerified(false);

        userDao.save(userEntity);

        emailService.sendVerificationEmail(req.getEmail(), verificationString);

        return ResponseEntity.ok(null);
    }

    public ResponseEntity<?> loginUserStart(LoginStartReq req) {
        if (!userDao.existsByEmail(req.getEmail())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        UserEntity userEntity = userDao.findByEmail(req.getEmail());
        if (!userEntity.getEmailVerified()) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_EMAIL_UNVERIFIED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

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

    public ResponseEntity<?> loginUserEnd(LoginCompleteReq req) {
        SrpEntity srpEntity = srpDao.findByUserEntity_EmailAndDeviceId(req.getEmail(), req.getDeviceId());
        if (srpEntity == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.SRP_SESSION_NOT_FOUND);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        srpDao.delete(srpEntity);

        if (srpEntity.getExpiryTime().isBefore(Instant.now())) {
            ApiError apiError = new ApiError(ApiErrorEnum.SRP_SESSION_EXPIRED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        BigInteger M1Server = srpFlow.calculateM1Server(srpEntity);
        BigInteger M1Client = new BigInteger(1, Base64.getDecoder().decode(req.getM1()));

        if (!M1Server.equals(M1Client)) {
            ApiError apiError = new ApiError(ApiErrorEnum.SRP_VERIFICATION_FAILED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        BigInteger M2Server = srpFlow.calculateM2Server(srpEntity, M1Client);

        UserEntity user = userDao.findByEmail(req.getEmail());
        String refreshToken = TokenGenerator.generateRefreshToken(32);
        Instant refreshExpiry = Instant.now().plus(30, ChronoUnit.MINUTES);

        SessionEntity sessionEntity = sessionDao.findByUserEntityAndDeviceId(user, req.getDeviceId());
        if (sessionEntity == null) {
            sessionEntity = new SessionEntity();
            sessionEntity.setUserEntity(user);
            sessionEntity.setDeviceId(req.getDeviceId());
        }
        sessionEntity.setRefreshTokenHash(TokenHasher.hashToken(refreshToken));
        sessionEntity.setExpiryTime(refreshExpiry);
        sessionDao.save(sessionEntity);

        LoginCompleteResp resp = new LoginCompleteResp();
        resp.setM2(Base64.getEncoder().encodeToString(M2Server.toByteArray()));
        resp.setSaltKey(user.getSaltKey());
        resp.setAccessToken(generateJwt(req.getEmail(), req.getDeviceId()));
        resp.setRefreshToken(refreshToken);
        resp.setRefreshTokenExpiryTime(refreshExpiry);

        return ResponseEntity.ok(resp);
    }

    public ResponseEntity<?> refreshJWT(RefreshReq req) {
        if (!userDao.existsByEmail(req.getEmail())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        Instant now = Instant.now();

        UserEntity userEntity = userDao.findByEmail(req.getEmail());

        SessionEntity sessionEntity = sessionDao.findByUserEntityAndDeviceId(userEntity, req.getDeviceId());
        if (sessionEntity == null || sessionEntity.getExpiryTime().isBefore(now)) {
            ApiError apiError = new ApiError(ApiErrorEnum.TOKEN_EXPIRED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        boolean verified = TokenHasher.verifyToken(req.getRefreshToken(), sessionEntity.getRefreshTokenHash());
        if (!verified) {
            ApiError apiError = new ApiError(ApiErrorEnum.TOKEN_VERIFICATION_FAILED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        RefreshResp resp = new RefreshResp();
        resp.setAccessToken(generateJwt(req.getEmail(), req.getDeviceId()));

        return ResponseEntity.ok(resp);
    }

    @Transactional
    public ResponseEntity<?> logout(RefreshReq req) {
        SessionEntity sessionEntity = sessionDao.findByUserEntity_EmailAndDeviceId(
                req.getEmail(),
                req.getDeviceId()
        );

        if (sessionEntity == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.SESSION_NOT_FOUND);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        boolean verified = TokenHasher.verifyToken(req.getRefreshToken(), sessionEntity.getRefreshTokenHash());
        if (!verified) {
            ApiError apiError = new ApiError(ApiErrorEnum.TOKEN_VERIFICATION_FAILED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        sessionDao.delete(sessionEntity);

        return ResponseEntity.ok(null);
    }

    @Transactional
    public ResponseEntity<?> verifyEmail(String token) {
        UserEntity userEntity = userDao.findByVerificationString(token);

        if (userEntity == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_VERIFICATION_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }
        if (userEntity.getVerificationExpiryTime().isBefore(Instant.now())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_VERIFICATION_EXPIRED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        userEntity.setVerificationString(null);
        userEntity.setVerificationExpiryTime(null);
        userEntity.setEmailVerified(true);
        userDao.save(userEntity);

        return ResponseEntity.ok("Email has been verified successfully");
    }


    private String generateJwt(String email, UUID deviceId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("deviceId", deviceId);
        return jwtService.generateToken(email, claims, 300);
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
