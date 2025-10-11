package com.security.passwordmanager.service;

import com.security.passwordmanager.api.authorization.*;
import com.security.passwordmanager.api.error.ApiError;
import com.security.passwordmanager.api.error.ApiErrorEnum;
import com.security.passwordmanager.config.TokenGenerator;
import com.security.passwordmanager.config.TokenHasher;
import com.security.passwordmanager.mapper.UserMapper;
import com.security.passwordmanager.model.authorization.*;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class AuthorizationService {

    private final UserMapper userMapper;
    private final JwtService jwtService;
    private final UserDao userDao;
    private final SessionDao sessionDao;

    private final Map<String, SrpSession> srpSessions = new ConcurrentHashMap<>();

    public ResponseEntity<?> registerUser(RegistrationReq req) {
        if (userDao.existsByEmail(req.getEmail())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        UserEntity userEntity = userMapper.toUserEntity(req);
        userEntity.setUserId(UUID.randomUUID());

        userEntity = userDao.save(userEntity);

        String refreshToken = TokenGenerator.generateRefreshToken(32);
        Instant refreshTokenExpiry = Instant.now().plus(12, ChronoUnit.HOURS);

        SessionEntity sessionEntity = new SessionEntity();
        sessionEntity.setUserEntity(userEntity);
        sessionEntity.setDeviceId(req.getDeviceId());
        sessionEntity.setRefreshTokenHash(TokenHasher.hashToken(refreshToken));
        sessionEntity.setExpiryTime(refreshTokenExpiry);

        sessionDao.save(sessionEntity);

        RegistrationResp resp = new RegistrationResp();
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
        SRP6GroupParameters group = SRP6StandardGroups.rfc5054_3072;
        Digest digest = new SHA256Digest();
        SecureRandom random = new SecureRandom();

        BigInteger N = group.getN();
        BigInteger g = group.getG();

        BigInteger v = new BigInteger(1, Base64.getDecoder().decode(userEntity.getVerifier()));

        BigInteger b = new BigInteger(256, random);
        BigInteger k = SRP6Util.calculateK(digest, N, g);
        BigInteger B = k.multiply(v).add(g.modPow(b, N)).mod(N);

        SrpSession session = new SrpSession(req.getEmail(), req.getA(), b, B, v);
        srpSessions.put(req.getEmail(), session);

        LoginStartResp resp = new LoginStartResp();
        resp.setSaltAuth(userEntity.getSaltAuth());
        resp.setB(Base64.getEncoder().encodeToString(B.toByteArray()));

        return ResponseEntity.ok(resp);
    }

    public ResponseEntity<?> loginUserEnd(LoginCompleteReq req) {
        SrpSession session = srpSessions.remove(req.getEmail());
        if (session == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.SRP_SESSION_NOT_FOUND);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        SRP6GroupParameters group = SRP6StandardGroups.rfc5054_3072;
        Digest digest = new SHA256Digest();

        BigInteger N = group.getN();
        BigInteger g = group.getG();

        BigInteger A = new BigInteger(1, Base64.getDecoder().decode(session.getA()));
        BigInteger B = session.getB();
        BigInteger b = session.getBpriv();
        BigInteger v = session.getVerifier();

        BigInteger u = SRP6Util.calculateU(digest, N, A, B);
        BigInteger S = A.multiply(v.modPow(u, N)).modPow(b, N);
        BigInteger M1_server = SRP6Util.calculateM1(digest, N, A, B, S);

        BigInteger M1_client = new BigInteger(1, Base64.getDecoder().decode(req.getM1()));
        if (!M1_server.equals(M1_client)) {
            ApiError apiError = new ApiError(ApiErrorEnum.SRP_VERIFICATION_FAILED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        BigInteger M2 = SRP6Util.calculateM2(digest, A, M1_client, S, B);

        UserEntity user = userDao.findByEmail(req.getEmail());
        String refreshToken = TokenGenerator.generateRefreshToken(32);
        Instant refreshExpiry = Instant.now().plus(12, ChronoUnit.HOURS);

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
        resp.setM2(Base64.getEncoder().encodeToString(M2.toByteArray()));
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

    private String generateJwt(String email, UUID deviceId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("deviceId", deviceId);
        return jwtService.generateToken(email, claims, 600);
    }

    private static class SrpSession {
        private final String email;
        private final String A;
        private final BigInteger bpriv;
        private final BigInteger B;
        private final BigInteger verifier;

        public SrpSession(String email, String A, BigInteger bpriv, BigInteger B, BigInteger verifier) {
            this.email = email;
            this.A = A;
            this.bpriv = bpriv;
            this.B = B;
            this.verifier = verifier;
        }

        public String getEmail() { return email; }
        public String getA() { return A; }
        public BigInteger getBpriv() { return bpriv; }
        public BigInteger getB() { return B; }
        public BigInteger getVerifier() { return verifier; }
    }

}
