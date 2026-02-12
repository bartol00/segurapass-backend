package com.security.passwordmanager;

import com.security.passwordmanager.api.authorization.*;
import com.security.passwordmanager.api.error.ApiError;
import com.security.passwordmanager.api.error.ApiErrorEnum;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.*;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class AuthorizationServiceIT extends AbstractPostgresIT {

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
        RegistrationReq registrationReq = generateRegistrationReq();
        registrationReq.setEmail("invalid@email.com");

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.registerUser(registrationReq);

        // then
        assertEquals(ApiErrorEnum.USER_EMAIL_INVALID.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.USER_EMAIL_INVALID.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldFailUserExistsErrorRegisterUser() {
        // given
        RegistrationReq registrationReq = generateRegistrationReq();
        doReturn(true).when(userDao).existsByEmail(registrationReq.getEmail());

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.registerUser(registrationReq);

        // then
        assertEquals(ApiErrorEnum.USER_EXISTS.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.USER_EXISTS.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldSucceedRegisterUser() {
        // given
        RegistrationReq registrationReq = generateRegistrationReq();

        // when
        ResponseEntity<?> response = authorizationService.registerUser(registrationReq);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(userDao.existsByEmail(registrationReq.getEmail()));
    }

    @Test
    void shouldFailUserNotExistsErrorLoginStart() {
        // given
        LoginStartReq loginStartReq = generateLoginStartReq();
        doReturn(false).when(userDao).existsByEmail(loginStartReq.getEmail());

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.loginUserStart(loginStartReq);

        // then
        assertEquals(ApiErrorEnum.USER_NOT_EXISTS.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.USER_NOT_EXISTS.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldFailUserEmailUnverifiedErrorLoginStart() {
        // given
        LoginStartReq loginStartReq = generateLoginStartReq();
        UserEntity userEntity = generateUserEntity();
        doReturn(userEntity).when(userDao).findByEmail(loginStartReq.getEmail());

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.loginUserStart(loginStartReq);

        // then
        assertEquals(ApiErrorEnum.USER_EMAIL_UNVERIFIED.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.USER_EMAIL_UNVERIFIED.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldSucceedLoginStart() {
        // given
        LoginStartReq loginStartReq = generateLoginStartReq();
        UserEntity userEntity = generateUserEntity();
        userEntity.setEmailVerified(true);
        doReturn(userEntity).when(userDao).findByEmail(loginStartReq.getEmail());

        // when
        ResponseEntity<LoginStartResp> response = (ResponseEntity<LoginStartResp>) authorizationService.loginUserStart(loginStartReq);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(response.getBody().getSaltAuth(), userEntity.getSaltAuth());
        assertNotEquals(0, srpDao.findAll().size());
    }

    @Test
    void shouldFailSrpEntityNullLoginEnd() {
        // given
        LoginCompleteReq loginCompleteReq = generateLoginCompleteReq();
        doReturn(null).when(srpDao).findByUserEntity_EmailAndDeviceId(loginCompleteReq.getEmail(), loginCompleteReq.getDeviceId());

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.loginUserEnd(loginCompleteReq);

        // then
        assertEquals(ApiErrorEnum.SRP_SESSION_NOT_FOUND.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.SRP_SESSION_NOT_FOUND.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldFailSrpEntityExpiredLoginEnd() {
        // given
        LoginCompleteReq loginCompleteReq = generateLoginCompleteReq();
        SrpEntity srpEntity = generateSrpEntity();
        srpEntity.setExpiryTime(Instant.now().minus(2, ChronoUnit.MINUTES));
        doReturn(srpEntity).when(srpDao).findByUserEntity_EmailAndDeviceId(loginCompleteReq.getEmail(), loginCompleteReq.getDeviceId());
        doNothing().when(srpDao).delete(any(SrpEntity.class));

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.loginUserEnd(loginCompleteReq);

        // then
        assertEquals(ApiErrorEnum.SRP_SESSION_EXPIRED.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.SRP_SESSION_EXPIRED.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldFailM1MismatchLoginEnd() {
        // given
        LoginCompleteReq loginCompleteReq = generateLoginCompleteReq();
        SrpEntity srpEntity = generateSrpEntity();
        doReturn(srpEntity).when(srpDao).findByUserEntity_EmailAndDeviceId(loginCompleteReq.getEmail(), loginCompleteReq.getDeviceId());
        doNothing().when(srpDao).delete(any(SrpEntity.class));
        doReturn(BigInteger.ONE).when(srpFlow).calculateM1Server(srpEntity);

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.loginUserEnd(loginCompleteReq);

        // then
        assertEquals(ApiErrorEnum.SRP_VERIFICATION_FAILED.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.SRP_VERIFICATION_FAILED.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldSucceedLoginEnd() {
        // given
        LoginCompleteReq loginCompleteReq = generateLoginCompleteReq();
        SrpEntity srpEntity = generateSrpEntity();
        UserEntity userEntity = generateUserEntity();
        doReturn(srpEntity).when(srpDao).findByUserEntity_EmailAndDeviceId(loginCompleteReq.getEmail(), loginCompleteReq.getDeviceId());
        doNothing().when(srpDao).delete(any(SrpEntity.class));
        doReturn(new BigInteger(1, Base64.getDecoder().decode(loginCompleteReq.getM1()))).when(srpFlow).calculateM1Server(srpEntity);
        doReturn(userEntity).when(userDao).findByEmail(loginCompleteReq.getEmail());
        doReturn(null).when(sessionDao).save(any(SessionEntity.class));

        // when
        ResponseEntity<LoginCompleteResp> response = (ResponseEntity<LoginCompleteResp>) authorizationService.loginUserEnd(loginCompleteReq);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userEntity.getSaltKey(), response.getBody().getSaltKey());
    }

    @Test
    void shouldFailUserNotExistsRefreshJwt() {
        // given
        RefreshReq refreshReq = generateRefreshReq();
        doReturn(false).when(userDao).existsByEmail(refreshReq.getEmail());

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.refreshJWT(refreshReq);

        // then
        assertEquals(ApiErrorEnum.USER_NOT_EXISTS.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.USER_NOT_EXISTS.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldFailSessionIsNullRefreshJwt() {
        // given
        RefreshReq refreshReq = generateRefreshReq();
        UserEntity userEntity = generateUserEntity();
        doReturn(true).when(userDao).existsByEmail(refreshReq.getEmail());
        doReturn(userEntity).when(userDao).findByEmail(refreshReq.getEmail());
        doReturn(null).when(sessionDao).findByUserEntityAndDeviceId(userEntity, refreshReq.getDeviceId());

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.refreshJWT(refreshReq);

        // then
        assertEquals(ApiErrorEnum.TOKEN_EXPIRED.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.TOKEN_EXPIRED.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldFailSessionExpiredRefreshJwt() {
        // given
        RefreshReq refreshReq = generateRefreshReq();
        UserEntity userEntity = generateUserEntity();
        SessionEntity sessionEntity = generateSessionEntity();
        sessionEntity.setExpiryTime(Instant.now().minus(2, ChronoUnit.MINUTES));
        doReturn(true).when(userDao).existsByEmail(refreshReq.getEmail());
        doReturn(userEntity).when(userDao).findByEmail(refreshReq.getEmail());
        doReturn(sessionEntity).when(sessionDao).findByUserEntityAndDeviceId(userEntity, refreshReq.getDeviceId());

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.refreshJWT(refreshReq);

        // then
        assertEquals(ApiErrorEnum.TOKEN_EXPIRED.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.TOKEN_EXPIRED.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldFailTokenUnverifiedRefreshJwt() {
        // given
        RefreshReq refreshReq = generateRefreshReq();
        UserEntity userEntity = generateUserEntity();
        SessionEntity sessionEntity = generateSessionEntity();
        doReturn(true).when(userDao).existsByEmail(refreshReq.getEmail());
        doReturn(userEntity).when(userDao).findByEmail(refreshReq.getEmail());
        doReturn(sessionEntity).when(sessionDao).findByUserEntityAndDeviceId(userEntity, refreshReq.getDeviceId());

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.refreshJWT(refreshReq);

        // then
        assertEquals(ApiErrorEnum.TOKEN_VERIFICATION_FAILED.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.TOKEN_VERIFICATION_FAILED.getMessage(), response.getBody().getMessage());
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
        ResponseEntity<?> response = authorizationService.refreshJWT(refreshReq);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void shouldFailSessionIsNullLogout() {
        // given
        RefreshReq refreshReq = generateRefreshReq();
        doReturn(null).when(sessionDao).findByUserEntity_EmailAndDeviceId(refreshReq.getEmail(), refreshReq.getDeviceId());

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.logout(refreshReq);

        // then
        assertEquals(ApiErrorEnum.SESSION_NOT_FOUND.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.SESSION_NOT_FOUND.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldFailTokenUnverifiedLogout() {
        // given
        RefreshReq refreshReq = generateRefreshReq();
        SessionEntity sessionEntity = generateSessionEntity();
        doReturn(sessionEntity).when(sessionDao).findByUserEntity_EmailAndDeviceId(refreshReq.getEmail(), refreshReq.getDeviceId());

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.logout(refreshReq);

        // then
        assertEquals(ApiErrorEnum.TOKEN_VERIFICATION_FAILED.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.TOKEN_VERIFICATION_FAILED.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldSucceedLogout() {
        // given
        RefreshReq refreshReq = generateRefreshReq();
        SessionEntity sessionEntity = generateSessionEntity();
        sessionEntity.setRefreshTokenHash(tokenHasher.hashToken(refreshReq.getRefreshToken()));
        doReturn(sessionEntity).when(sessionDao).findByUserEntity_EmailAndDeviceId(refreshReq.getEmail(), refreshReq.getDeviceId());
        doNothing().when(sessionDao).delete(any(SessionEntity.class));

        // when
        ResponseEntity<?> response = authorizationService.logout(refreshReq);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void shouldFailUserIsNullVerifyEmail() {
        // given
        doReturn(null).when(userDao).findByVerificationString(tokenHasher.generateSha256(emailVerificationToken));

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.verifyEmail(emailVerificationToken);

        // then
        assertEquals(ApiErrorEnum.USER_VERIFICATION_NOT_EXISTS.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.USER_VERIFICATION_NOT_EXISTS.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldFailUserVerificationExpiredVerifyEmail() {
        // given
        UserEntity userEntity = generateUserEntity();
        userEntity.setVerificationExpiryTime(Instant.now().minus(2, ChronoUnit.MINUTES));
        doReturn(userEntity).when(userDao).findByVerificationString(tokenHasher.generateSha256(emailVerificationToken));

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) authorizationService.verifyEmail(emailVerificationToken);

        // then
        assertEquals(ApiErrorEnum.USER_VERIFICATION_EXPIRED.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.USER_VERIFICATION_EXPIRED.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldSucceedVerifyEmail() {
        // given
        UserEntity userEntity = generateUserEntity();
        doReturn(userEntity).when(userDao).findByVerificationString(tokenHasher.generateSha256(emailVerificationToken));

        // when
        ResponseEntity<?> response = authorizationService.verifyEmail(emailVerificationToken);

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
