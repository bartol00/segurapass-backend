package com.security.passwordmanager;

import com.security.passwordmanager.api.authorization.*;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.*;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static com.security.passwordmanager.exceptions.ErrorEnum.*;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
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
    private SessionDao sessionDao;
    @MockitoSpyBean
    private SrpFlow srpFlow;
    @MockitoBean
    private EmailService emailService;

    @BeforeAll
    void setup() {
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
        assertTrue(userDao.existsByEmail(req.getEmail()));
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
        assertEquals(USER_EMAIL_UNVERIFIED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_EMAIL_UNVERIFIED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedLoginStart() {
        // given
        LoginStartReq req = generateLoginStartReq();
        UserEntity userEntity = generateUserEntity();
        userEntity.setEmailVerified(true);
        doReturn(userEntity).when(userDao).findByEmail(req.getEmail());

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
        LoginCompleteReq req = generateLoginCompleteReq();
        SrpEntity srpEntity = generateSrpEntity();
        UserEntity userEntity = generateUserEntity();
        doReturn(srpEntity).when(srpDao).findByUserEntity_EmailAndDeviceId(req.getEmail(), req.getDeviceId());
        doNothing().when(srpDao).delete(any(SrpEntity.class));
        doReturn(new BigInteger(1, Base64.getDecoder().decode(req.getM1()))).when(srpFlow).calculateM1Server(srpEntity);
        doReturn(userEntity).when(userDao).findByEmail(req.getEmail());
        doReturn(null).when(sessionDao).save(any(SessionEntity.class));

        // when
        ResponseEntity<LoginCompleteResp> response = authorizationService.loginUserEnd(req);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userEntity.getSaltKey(), response.getBody().getSaltKey());
    }

    @Test
    void shouldFailUserNotExistsRefreshJwt() {
        // given
        RefreshReq req = generateRefreshReq();
        doReturn(false).when(userDao).existsByEmail(req.getEmail());

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.refreshJWT(req));

        // then
        assertEquals(USER_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailSessionIsNullRefreshJwt() {
        // given
        RefreshReq req = generateRefreshReq();
        UserEntity userEntity = generateUserEntity();
        doReturn(true).when(userDao).existsByEmail(req.getEmail());
        doReturn(userEntity).when(userDao).findByEmail(req.getEmail());
        doReturn(null).when(sessionDao).findByUserEntityAndDeviceId(userEntity, req.getDeviceId());

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.refreshJWT(req));

        // then
        assertEquals(TOKEN_EXPIRED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_EXPIRED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailSessionExpiredRefreshJwt() {
        // given
        RefreshReq req = generateRefreshReq();
        UserEntity userEntity = generateUserEntity();
        SessionEntity sessionEntity = generateSessionEntity();
        sessionEntity.setExpiryTime(Instant.now().minus(2, ChronoUnit.MINUTES));
        doReturn(true).when(userDao).existsByEmail(req.getEmail());
        doReturn(userEntity).when(userDao).findByEmail(req.getEmail());
        doReturn(sessionEntity).when(sessionDao).findByUserEntityAndDeviceId(userEntity, req.getDeviceId());

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.refreshJWT(req));

        // then
        assertEquals(TOKEN_EXPIRED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_EXPIRED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailTokenUnverifiedRefreshJwt() {
        // given
        RefreshReq req = generateRefreshReq();
        UserEntity userEntity = generateUserEntity();
        SessionEntity sessionEntity = generateSessionEntity();
        doReturn(true).when(userDao).existsByEmail(req.getEmail());
        doReturn(userEntity).when(userDao).findByEmail(req.getEmail());
        doReturn(sessionEntity).when(sessionDao).findByUserEntityAndDeviceId(userEntity, req.getDeviceId());

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.refreshJWT(req));

        // then
        assertEquals(TOKEN_VERIFICATION_FAILED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_VERIFICATION_FAILED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedRefreshJwt() {
        // given
        RefreshReq refreshReq = generateRefreshReq();
        UserEntity userEntity = generateUserEntity();
        SessionEntity sessionEntity = generateSessionEntity();
        sessionEntity.setRefreshTokenHash(tokenHasher.hashToken(refreshReq.getRefreshToken()));
        doReturn(true).when(userDao).existsByEmail(refreshReq.getEmail());
        doReturn(userEntity).when(userDao).findByEmail(refreshReq.getEmail());
        doReturn(sessionEntity).when(sessionDao).findByUserEntityAndDeviceId(userEntity, refreshReq.getDeviceId());

        // when
        ResponseEntity<RefreshResp> response = authorizationService.refreshJWT(refreshReq);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void shouldFailSessionIsNullLogout() {
        // given
        RefreshReq req = generateRefreshReq();
        doReturn(null).when(sessionDao).findByUserEntity_EmailAndDeviceId(req.getEmail(), req.getDeviceId());

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.logout(req));

        // then
        assertEquals(SESSION_NOT_FOUND.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(SESSION_NOT_FOUND.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailTokenUnverifiedLogout() {
        // given
        RefreshReq req = generateRefreshReq();
        SessionEntity sessionEntity = generateSessionEntity();
        doReturn(sessionEntity).when(sessionDao).findByUserEntity_EmailAndDeviceId(req.getEmail(), req.getDeviceId());

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.logout(req));

        // then
        assertEquals(TOKEN_VERIFICATION_FAILED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_VERIFICATION_FAILED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedLogout() {
        // given
        RefreshReq req = generateRefreshReq();
        SessionEntity sessionEntity = generateSessionEntity();
        sessionEntity.setRefreshTokenHash(tokenHasher.hashToken(req.getRefreshToken()));
        doReturn(sessionEntity).when(sessionDao).findByUserEntity_EmailAndDeviceId(req.getEmail(), req.getDeviceId());
        doNothing().when(sessionDao).delete(any(SessionEntity.class));

        // when
        ResponseEntity<Void> response = authorizationService.logout(req);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void shouldFailUserIsNullVerifyEmail() {
        // given
        doReturn(null).when(userDao).findByVerificationString(tokenHasher.generateSha256(emailVerificationToken));

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.verifyEmail(emailVerificationToken));

        // then
        assertEquals(USER_VERIFICATION_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_VERIFICATION_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailUserVerificationExpiredVerifyEmail() {
        // given
        UserEntity userEntity = generateUserEntity();
        userEntity.setVerificationExpiryTime(Instant.now().minus(2, ChronoUnit.MINUTES));
        doReturn(userEntity).when(userDao).findByVerificationString(tokenHasher.generateSha256(emailVerificationToken));

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.verifyEmail(emailVerificationToken));

        // then
        assertEquals(USER_VERIFICATION_EXPIRED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_VERIFICATION_EXPIRED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedVerifyEmail() {
        // given
        UserEntity userEntity = generateUserEntity();
        doReturn(userEntity).when(userDao).findByVerificationString(tokenHasher.generateSha256(emailVerificationToken));

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
        refreshReq.setEmail(email);
        refreshReq.setDeviceId(UUID.randomUUID());
        refreshReq.setRefreshToken("refreshToken");
        return refreshReq;
    }

    private UserEntity generateUserEntity() {
        UserEntity userEntity = new UserEntity();
        userEntity.setId(1L);
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

    private SessionEntity generateSessionEntity() {
        SessionEntity sessionEntity = new SessionEntity();
        sessionEntity.setId(1L);
        sessionEntity.setDeviceId(UUID.randomUUID());
        sessionEntity.setRefreshTokenHash("refreshTokenHash");
        sessionEntity.setExpiryTime(Instant.now().plus(30, ChronoUnit.MINUTES));
        sessionEntity.setUserEntity(generateUserEntity());
        return sessionEntity;
    }

}
