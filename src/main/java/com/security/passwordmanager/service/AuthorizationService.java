package com.security.passwordmanager.service;

import com.security.passwordmanager.api.authorization.*;
import com.security.passwordmanager.api.error.ApiError;
import com.security.passwordmanager.api.error.ApiErrorEnum;
import com.security.passwordmanager.config.TokenGenerator;
import com.security.passwordmanager.config.TokenHasher;
import com.security.passwordmanager.config.UserKeyLoader;
import com.security.passwordmanager.mapper.UserMapper;
import com.security.passwordmanager.model.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthorizationService {

    private final UserMapper userMapper;
    private final JwtService jwtService;
    private final UserDao userDao;
    private final SessionDao sessionDao;
    private final NonceDao nonceDao;

    public ResponseEntity<?> registerUser(RegistrationReq req) {
        if (userDao.existsByEmail(req.getEmail())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        UserEntity userEntity = userMapper.toUserEntity(req);
        userEntity.setUserId(UUID.randomUUID());

        userEntity = userDao.save(userEntity);

        String refreshToken = TokenGenerator.generateRefreshToken(32);
        Instant refreshTokenExpiry = Instant.now().plus(24, ChronoUnit.HOURS);

        SessionEntity sessionEntity = new SessionEntity();
        sessionEntity.setUserEntity(userEntity);
        sessionEntity.setDeviceId(req.getDeviceId());
        sessionEntity.setRefreshTokenHash(TokenHasher.hashToken(refreshToken));
        sessionEntity.setExpiryTime(refreshTokenExpiry);

        sessionDao.save(sessionEntity);

        LoginCompleteResp resp = new LoginCompleteResp();
        resp.setRefreshToken(refreshToken);
        resp.setAccessToken(generateJwt(req.getEmail(), req.getDeviceId()));
        resp.setRefreshTokenExpiryTime(refreshTokenExpiry);

        return ResponseEntity.ok(resp);
    }

    public ResponseEntity<?> loginUserStart(LoginStartReq req) {
        if (!userDao.existsByEmail(req.getEmail())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        UserEntity userEntity = userDao.findByEmail(req.getEmail());

        UUID nonce = UUID.randomUUID();

        NonceEntity nonceEntity = nonceDao.findByUserEntityAndDeviceId(userEntity, req.getDeviceId());
        if (nonceEntity == null) {
            nonceEntity = new NonceEntity();
            nonceEntity.setNonce(nonce);
            nonceEntity.setDeviceId(req.getDeviceId());
            nonceEntity.setNonceExpiry(Instant.now().plus(10, ChronoUnit.MINUTES));
            nonceEntity.setUserEntity(userEntity);
        } else {
            nonceEntity.setNonce(nonce);
            nonceEntity.setNonceExpiry(Instant.now().plus(10, ChronoUnit.MINUTES));
        }

        nonceDao.save(nonceEntity);

        LoginStartResp resp = new LoginStartResp();
        resp.setNonce(nonce);
        resp.setKeyIv(userEntity.getKeyIv());
        resp.setEncryptedPrivateKey(userEntity.getEncryptedPrivateKey());

        return ResponseEntity.ok(resp);
    }

    public ResponseEntity<?> loginUserEnd(LoginCompleteReq req) {
        Instant now = Instant.now();

        if (!userDao.existsByEmail(req.getEmail())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        UserEntity userEntity = userDao.findByEmail(req.getEmail());

        NonceEntity nonceEntity = nonceDao.findByUserEntityAndDeviceId(userEntity, req.getDeviceId());
        if (nonceEntity == null || nonceEntity.getNonceExpiry().isBefore(now)) {
            ApiError apiError = new ApiError(ApiErrorEnum.NONCE_EXPIRED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        try {
            byte[] nonceBytes = nonceEntity.getNonce().toString().getBytes(StandardCharsets.UTF_8);
            byte[] nonceSignature = Base64.getDecoder().decode(req.getSignedNonce());

            nonceDao.delete(nonceEntity);

            PublicKey userPublicKey = UserKeyLoader.getPublicKeyFromBase64(userEntity.getPublicKeyPem());

            boolean verified = UserKeyLoader.verifySignature(userPublicKey, nonceBytes, nonceSignature);

            if (!verified) {
                ApiError apiError = new ApiError(ApiErrorEnum.NONCE_VERIFICATION_FAILED);
                return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
            }

            String refreshToken = TokenGenerator.generateRefreshToken(32);
            Instant refreshTokenExpiry = now.plus(24, ChronoUnit.HOURS);

            SessionEntity sessionEntity = sessionDao.findByUserEntityAndDeviceId(userEntity, req.getDeviceId());
            if (sessionEntity == null) {
                sessionEntity = new SessionEntity();
                sessionEntity.setUserEntity(userEntity);
                sessionEntity.setDeviceId(req.getDeviceId());
                sessionEntity.setRefreshTokenHash(TokenHasher.hashToken(refreshToken));
                sessionEntity.setExpiryTime(refreshTokenExpiry);
            } else {
                sessionEntity.setRefreshTokenHash(TokenHasher.hashToken(refreshToken));
                sessionEntity.setExpiryTime(refreshTokenExpiry);
            }

            sessionDao.save(sessionEntity);

            LoginCompleteResp resp = new LoginCompleteResp();
            resp.setRefreshToken(refreshToken);
            resp.setAccessToken(generateJwt(req.getEmail(), req.getDeviceId()));
            resp.setRefreshTokenExpiryTime(refreshTokenExpiry);

            return ResponseEntity.ok(resp);
        } catch (Exception e) {
            // e.printStackTrace();
            ApiError apiError = new ApiError(ApiErrorEnum.NONCE_VERIFICATION_ERROR);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }
    }

    public ResponseEntity<?> refreshJWT(RefreshReq req) {
        Instant now = Instant.now();

        if (!userDao.existsByEmail(req.getEmail())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

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

    private String generateJwt(String email, UUID deviceId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("deviceId", deviceId);
        return jwtService.generateToken(email, claims, 600);
    }

}
