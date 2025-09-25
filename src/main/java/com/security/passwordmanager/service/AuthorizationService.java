package com.security.passwordmanager.service;

import com.security.passwordmanager.api.authorization.LoginCompleteResp;
import com.security.passwordmanager.api.authorization.LoginStartReq;
import com.security.passwordmanager.api.authorization.RegistrationReq;
import com.security.passwordmanager.api.error.ApiError;
import com.security.passwordmanager.api.error.ApiErrorEnum;
import com.security.passwordmanager.config.TokenGenerator;
import com.security.passwordmanager.config.TokenHasher;
import com.security.passwordmanager.mapper.UserMapper;
import com.security.passwordmanager.model.SessionDao;
import com.security.passwordmanager.model.SessionEntity;
import com.security.passwordmanager.model.UserDao;
import com.security.passwordmanager.model.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthorizationService {

    private final UserMapper userMapper;
    private final JwtService jwtService;
    private final UserDao userDao;
    private final SessionDao sessionDao;

    public ResponseEntity<?> registerUser(RegistrationReq req) {
        if (userDao.existsByEmail(req.getEmail())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        UserEntity userEntity = userMapper.toUserEntity(req);
        userEntity.setUserId(UUID.randomUUID());

        userEntity = userDao.save(userEntity);

        String refreshToken = TokenGenerator.generateRefreshToken(32);

        SessionEntity sessionEntity = new SessionEntity();
        sessionEntity.setUserEntity(userEntity);
        sessionEntity.setDeviceId(req.getDeviceId());
        sessionEntity.setRefreshTokenHash(TokenHasher.hashToken(refreshToken));
        sessionEntity.setExpiryTime(Instant.now().plus(24, ChronoUnit.HOURS));

        sessionDao.save(sessionEntity);

        LoginCompleteResp resp = new LoginCompleteResp();
        resp.setRefreshToken(refreshToken);
        resp.setAccessToken(generateJwt(req.getEmail(), req.getDeviceId()));

        return ResponseEntity.ok(resp);
    }

    public ResponseEntity<LoginCompleteResp> loginUser(LoginStartReq req) {
        System.out.println(req.getEmail());
        System.out.println(req.getDeviceId());
        return null;
    }

    private String generateJwt(String email, UUID deviceId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("deviceId", deviceId);
        return jwtService.generateToken(email, claims, 600);
    }

}
