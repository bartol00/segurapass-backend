package com.security.passwordmanager;

import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.SessionRedisEntity;
import com.security.passwordmanager.redis.entities.UserRedisEntity;
import org.junit.jupiter.api.AfterEach;
import xyz.segurapass.api.authorization.*;
import com.security.passwordmanager.exceptions.AuthorizationException;
import com.security.passwordmanager.helpers.EmailService;
import com.security.passwordmanager.helpers.SrpFlow;
import com.security.passwordmanager.helpers.TokenHasher;
import com.security.passwordmanager.model.authorization.*;
import com.security.passwordmanager.service.AuthorizationService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.*;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static com.security.passwordmanager.exceptions.ErrorEnum.*;

@Slf4j
@SpringBootTest
public class AuthorizationServiceTest extends AbstractTestInitializer {

    private final String email = "me@gmail.com";
    private final String emailVerificationToken = "verification token";

    @Autowired
    private AuthorizationService authorizationService;
    @Autowired
    private TokenHasher tokenHasher;
    @MockitoSpyBean
    private UserDao userDao;
    @MockitoSpyBean
    private SrpDao srpDao;
    @MockitoSpyBean
    private SrpFlow srpFlow;
    @MockitoBean
    private EmailService emailService;
    @MockitoSpyBean
    private RedisService redisService;

    @AfterEach
    void cleanup() {
        userDao.deleteAll();
    }

    @Test
    void shouldFailInvalidEmailErrorRegisterUser() {
        // given
        RegistrationReq req = generateRegistrationReq();
        req.setEmail("invalid@email.com");

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.registerUser(req));

        // then
        assertEquals(USER_EMAIL_INVALID.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_EMAIL_INVALID.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailUserExistsErrorRegisterUser() {
        // given
        RegistrationReq req = generateRegistrationReq();
        doReturn(true).when(userDao).existsByEmail(req.getEmail());

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.registerUser(req));

        // then
        assertEquals(USER_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedRegisterUser() {
        // given
        RegistrationReq req = generateRegistrationReq();

        // when
        ResponseEntity<Void> response = authorizationService.registerUser(req);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void shouldFailUserNotExistsErrorLoginStart() {
        // given
        LoginStartReq req = generateLoginStartReq();
        doReturn(false).when(userDao).existsByEmail(req.getEmail());

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.loginUserStart(req));

        // then
        assertEquals(USER_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailUserEmailUnverifiedErrorLoginStart() {
        // given
        LoginStartReq req = generateLoginStartReq();
        UserEntity userEntity = generateUserEntity();
        doReturn(userEntity).when(userDao).findByEmail(req.getEmail());

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.loginUserStart(req));

        // then
        assertEquals(USER_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedLoginStart() {
        // given
        LoginStartReq req = generateLoginStartReq();
        UserEntity userEntity = generateUserEntity();
        userEntity.setEmailVerified(true);
        userDao.save(userEntity);

        // when
        ResponseEntity<LoginStartResp> response = authorizationService.loginUserStart(req);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(response.getBody().getSaltAuth(), userEntity.getSaltAuth());
        assertNotEquals(0, srpDao.findAll().size());
    }

    @Test
    void shouldFailSrpEntityNullLoginEnd() {
        // given
        LoginCompleteReq req = generateLoginCompleteReq();
        doReturn(null).when(srpDao).findByUserEntity_EmailAndDeviceId(req.getEmail(), req.getDeviceId());

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.loginUserEnd(req));

        // then
        assertEquals(SRP_SESSION_NOT_FOUND.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(SRP_SESSION_NOT_FOUND.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailSrpEntityExpiredLoginEnd() {
        // given
        LoginCompleteReq req = generateLoginCompleteReq();
        SrpEntity srpEntity = generateSrpEntity();
        srpEntity.setExpiryTime(Instant.now().minus(2, ChronoUnit.MINUTES));
        doReturn(srpEntity).when(srpDao).findByUserEntity_EmailAndDeviceId(req.getEmail(), req.getDeviceId());
        doNothing().when(srpDao).delete(any(SrpEntity.class));

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.loginUserEnd(req));

        // then
        assertEquals(SRP_SESSION_EXPIRED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(SRP_SESSION_EXPIRED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailM1MismatchLoginEnd() {
        // given
        LoginCompleteReq req = generateLoginCompleteReq();
        SrpEntity srpEntity = generateSrpEntity();
        doReturn(srpEntity).when(srpDao).findByUserEntity_EmailAndDeviceId(req.getEmail(), req.getDeviceId());
        doNothing().when(srpDao).delete(any(SrpEntity.class));
        doReturn(BigInteger.ONE).when(srpFlow).calculateM1Server(srpEntity);

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.loginUserEnd(req));

        // then
        assertEquals(SRP_VERIFICATION_FAILED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(SRP_VERIFICATION_FAILED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedLoginEnd() {
        // given
        MDC.put("clientIp", "127.0.0.1");
        LoginCompleteReq req = generateLoginCompleteReq();
        SrpEntity srpEntity = generateSrpEntity();
        UserEntity userEntity = generateUserEntity();
        doReturn(srpEntity).when(srpDao).findByUserEntity_EmailAndDeviceId(req.getEmail(), req.getDeviceId());
        doNothing().when(srpDao).delete(any(SrpEntity.class));
        doReturn(new BigInteger(1, Base64.getDecoder().decode(req.getM1()))).when(srpFlow).calculateM1Server(srpEntity);
        doReturn(userEntity).when(userDao).findByEmail(req.getEmail());
        doNothing().when(redisService).save(any(String.class), any(Object.class), any(Duration.class));

        // when
        ResponseEntity<LoginCompleteResp> response = authorizationService.loginUserEnd(req);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userEntity.getSaltKey(), response.getBody().getSaltKey());

        MDC.clear();
    }

    @Test
    void shouldFailRefreshTokenNotExistsRefreshJwt() {
        // given
        RefreshReq req = generateRefreshReq();
        String redisKey = "segurapass:session:" + tokenHasher.generateSha256(req.getRefreshToken());
        doReturn(false).when(redisService).exists(redisKey);

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.refreshJWT(req));

        // then
        assertEquals(TOKEN_EXPIRED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_EXPIRED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedRefreshJwt() {
        // given
        RefreshReq req = generateRefreshReq();
        UserEntity userEntity = generateUserEntity();
        userDao.save(userEntity);
        String redisKey = "segurapass:session:" + tokenHasher.generateSha256(req.getRefreshToken());
        SessionRedisEntity sessionRedisEntity = new SessionRedisEntity(
                userEntity.getUserId(),
                UUID.randomUUID()
        );
        doReturn(true).when(redisService).exists(redisKey);
        doReturn(sessionRedisEntity).when(redisService).get(redisKey, SessionRedisEntity.class);

        // when
        ResponseEntity<RefreshResp> response = authorizationService.refreshJWT(req);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void shouldFailSessionIsNullLogout() {
        // given
        RefreshReq req = generateRefreshReq();
        String redisKey = "segurapass:session:" + tokenHasher.generateSha256(req.getRefreshToken());
        doReturn(false).when(redisService).exists(redisKey);

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.logout(req));

        // then
        assertEquals(TOKEN_EXPIRED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_EXPIRED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedLogout() {
        // given
        RefreshReq req = generateRefreshReq();
        UserEntity userEntity = generateUserEntity();
        String redisKey = "segurapass:session:" + tokenHasher.generateSha256(req.getRefreshToken());
        SessionRedisEntity sessionRedisEntity = new SessionRedisEntity(
                userEntity.getUserId(),
                UUID.randomUUID()
        );
        doReturn(true).when(redisService).exists(redisKey);
        doReturn(sessionRedisEntity).when(redisService).get(redisKey, SessionRedisEntity.class);

        // when
        ResponseEntity<Void> response = authorizationService.logout(req);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void shouldFailEmailNotExistsVerifyEmail() {
        // given
        String redisKey = "segurapass:email_unverified:" + tokenHasher.generateSha256(emailVerificationToken);
        doReturn(false).when(redisService).exists(redisKey);

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.verifyEmail(emailVerificationToken));

        // then
        assertEquals(USER_VERIFICATION_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_VERIFICATION_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailUserAlreadyExistsVerifyEmail() {
        // given
        RegistrationReq req = generateRegistrationReq();
        String redisKey = "segurapass:email_unverified:" + tokenHasher.generateSha256(emailVerificationToken);
        UserRedisEntity userRedisEntity = new UserRedisEntity(
                UUID.randomUUID(),
                req.getEmail(),
                req.getSaltAuth(),
                req.getVerifier(),
                req.getSaltKey(),
                Instant.now()
        );
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
        doReturn(true).when(redisService).exists(redisKey);
        doReturn(userRedisEntity).when(redisService).get(redisKey, UserRedisEntity.class);
        doNothing().when(redisService).delete(redisKey);

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.verifyEmail(emailVerificationToken));

        // then
        assertEquals(USER_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedVerifyEmail() {
        // given
        RegistrationReq req = generateRegistrationReq();
        String redisKey = "segurapass:email_unverified:" + tokenHasher.generateSha256(emailVerificationToken);
        UserRedisEntity userRedisEntity = new UserRedisEntity(
                UUID.randomUUID(),
                req.getEmail(),
                req.getSaltAuth(),
                req.getVerifier(),
                req.getSaltKey(),
                Instant.now()
        );
        doReturn(true).when(redisService).exists(redisKey);
        doReturn(userRedisEntity).when(redisService).get(redisKey, UserRedisEntity.class);
        doNothing().when(redisService).delete(redisKey);

        // when
        ResponseEntity<String> response = authorizationService.verifyEmail(emailVerificationToken);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    private RegistrationReq generateRegistrationReq() {
        RegistrationReq registrationReq = new RegistrationReq();
        registrationReq.setEmail(email);
        registrationReq.setVerifier("verifier");
        registrationReq.setSaltKey("saltKey");
        registrationReq.setSaltAuth("saltAuth");
        registrationReq.setDeviceId(UUID.randomUUID());
        return registrationReq;
    }

    private LoginStartReq generateLoginStartReq() {
        LoginStartReq loginStartReq = new LoginStartReq();
        loginStartReq.setEmail(email);
        loginStartReq.setDeviceId(UUID.randomUUID());
        loginStartReq.setA("publicA");
        return loginStartReq;
    }

    private LoginCompleteReq generateLoginCompleteReq() {
        LoginCompleteReq loginCompleteReq = new LoginCompleteReq();
        loginCompleteReq.setEmail(email);
        loginCompleteReq.setDeviceId(UUID.randomUUID());
        loginCompleteReq.setM1("M1Client");
        return loginCompleteReq;
    }

    private RefreshReq generateRefreshReq() {
        RefreshReq refreshReq = new RefreshReq();
        refreshReq.setRefreshToken("refreshToken");
        return refreshReq;
    }

    private UserEntity generateUserEntity() {
        UserEntity userEntity = new UserEntity();
        userEntity.setUserId(UUID.randomUUID());
        userEntity.setEmail(email);
        userEntity.setSaltAuth("saltAuth");
        userEntity.setVerifier("verifier");
        userEntity.setSaltKey("saltKey");
        userEntity.setVerificationString(tokenHasher.generateSha256(emailVerificationToken));
        userEntity.setVerificationExpiryTime(Instant.now().plus(1, ChronoUnit.DAYS));
        userEntity.setEmailVerified(false);
        return userEntity;
    }
    
    private SrpEntity generateSrpEntity() {
        SrpEntity srpEntity = new SrpEntity();
        srpEntity.setId(1L);
        srpEntity.setA("publicA");
        srpEntity.setBpriv("privateB");
        srpEntity.setB("publicB");
        srpEntity.setVerifier("verifier");
        srpEntity.setDeviceId(UUID.randomUUID());
        srpEntity.setUserEntity(generateUserEntity());
        srpEntity.setExpiryTime(Instant.now().plus(30, ChronoUnit.MINUTES));
        return srpEntity;
    }

}
