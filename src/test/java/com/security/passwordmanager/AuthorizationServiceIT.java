package com.security.passwordmanager;

import com.security.passwordmanager.helpers.*;
import com.security.passwordmanager.model.audit.AuditLogDao;
import com.security.passwordmanager.model.mfa.TotpDao;
import com.security.passwordmanager.model.mfa.TotpEntity;
import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import xyz.segurapass.api.authorization.*;
import com.security.passwordmanager.exceptions.AuthorizationException;
import com.security.passwordmanager.model.authorization.*;
import com.security.passwordmanager.service.AuthorizationService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.*;

import java.math.BigInteger;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static com.security.passwordmanager.exceptions.ErrorEnum.*;
import static com.security.passwordmanager.shared.HelperMethods.*;

@Slf4j
@SpringBootTest
public class AuthorizationServiceIT extends AbstractTestInitializer {

    @Autowired
    private AuthorizationService authorizationService;
    @Autowired
    private TokenHasher tokenHasher;
    @Autowired
    private TokenGenerator tokenGenerator;
    @Autowired
    private UserDao userDao;
    @Autowired
    private AuditLogDao auditLogDao;
    @Autowired
    private TotpDao totpDao;
    @Autowired
    private SrpFlow srpFlow;
    @Autowired
    private RedisService redisService;
    @Autowired
    private EncryptionService encryptionService;
    @MockitoBean
    private EmailService emailService;

    @BeforeEach
    void setup() {
        UserEntity userEntity = generateUserEntity();
        userDao.save(userEntity);
        MDC.put("clientIp", "127.0.0.1");
    }

    @AfterEach
    void cleanup() {
        totpDao.deleteAll();
        userDao.deleteAll();
        auditLogDao.deleteAll();
        redisService.clearAll();
        MDC.clear();
    }

    @Test
    void shouldFailInvalidEmailErrorRegisterUser() {
        // given
        RegistrationReq req = generateRegistrationReq("invalid@email.com");

        // when
        AuthorizationException ex = assertThrows(
                AuthorizationException.class,
                () -> authorizationService.registerUser(req)
        );

        // then
        assertEquals(USER_EMAIL_INVALID.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_EMAIL_INVALID.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailUserAlreadyExistsErrorRegisterUser() {
        // given
        RegistrationReq req = generateRegistrationReq(email);

        // when
        AuthorizationException ex = assertThrows(
                AuthorizationException.class,
                () -> authorizationService.registerUser(req)
        );

        // then
        assertEquals(USER_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailEmailPendingVerificationRegisterUser() {
        // given
        String email = "unregistered@gmail.com";
        String emailHash = tokenHasher.generateSha256Email(email);
        String redisEmailKey = RedisKeys.emailUnverifiedEmail(emailHash);
        RegistrationReq req = generateRegistrationReq(email);
        redisService.save(
                redisEmailKey,
                null,
                Duration.of(10, ChronoUnit.MINUTES)
        );
        assertTrue(redisService.exists(redisEmailKey));

        // when
        AuthorizationException ex = assertThrows(
                AuthorizationException.class,
                () -> authorizationService.registerUser(req)
        );

        // then
        assertEquals(EMAIL_PENDING_VERIFICATION.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(EMAIL_PENDING_VERIFICATION.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedRegisterUser() {
        // given
        RegistrationReq req = generateRegistrationReq("unregistered@gmail.com");

        // when
        ResponseEntity<Void> response = authorizationService.registerUser(req);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(emailService).sendVerificationEmail(any(), any());
    }

    @Test
    void shouldFailUserIsNullErrorLoginStart() {
        // given
        LoginStartReq req = generateLoginStartReq("unregistered@gmail.com");

        // when
        AuthorizationException ex = assertThrows(
                AuthorizationException.class,
                () -> authorizationService.loginUserStart(req)
        );

        // then
        assertEquals(USER_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedLoginStart() {
        // given
        LoginStartReq req = generateLoginStartReq(email);
        UserEntity userEntity = userDao.findByEmail(email);
        String redisKey = RedisKeys.srp(
                userEntity.getUserId().toString(),
                req.getDeviceId().toString()
        );
        assertFalse(redisService.exists(redisKey));

        // when
        ResponseEntity<LoginStartResp> response = authorizationService.loginUserStart(req);

        // then
        assertTrue(redisService.exists(redisKey));
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertArrayEquals(response.getBody().getSaltAuth(), userEntity.getSaltAuthBytes());
    }

    @Test
    void shouldFailUserIsNullLoginEnd() {
        // given
        LoginCompleteReq req = generateLoginCompleteReq("unregistered@gmail.com", "M1");

        // when
        AuthorizationException ex = assertThrows(
                AuthorizationException.class,
                () -> authorizationService.loginUserEnd(req)
        );

        // then
        assertEquals(USER_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailTokenNotFoundLoginEnd() {
        // given
        LoginCompleteReq req = generateLoginCompleteReq(email, "M1");

        // when
        AuthorizationException ex = assertThrows(
                AuthorizationException.class,
                () -> authorizationService.loginUserEnd(req)
        );

        // then
        assertEquals(TOKEN_NOT_FOUND.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_NOT_FOUND.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailM1MismatchLoginEnd() {
        // given
        String A = Base64.getEncoder().encodeToString(BigInteger.TEN.toByteArray());
        UserEntity userEntity = userDao.findByEmail(email);
        SrpRedisEntity srpRedisEntity = srpFlow.beginFlow(A, userEntity);
        LoginCompleteReq req = generateLoginCompleteReq(email, "M1");
        String redisKey = RedisKeys.srp(
                userEntity.getUserId().toString(),
                req.getDeviceId().toString()
        );
        redisService.save(
                redisKey,
                srpRedisEntity,
                Duration.of(10, ChronoUnit.SECONDS)
        );
        assertTrue(redisService.exists(redisKey));

        // when
        AuthorizationException ex = assertThrows(AuthorizationException.class, () -> authorizationService.loginUserEnd(req));

        // then
        assertEquals(SRP_VERIFICATION_FAILED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(SRP_VERIFICATION_FAILED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedLoginEnd() {
        // given
        String A = Base64.getEncoder().encodeToString(BigInteger.TEN.toByteArray());
        UserEntity userEntity = userDao.findByEmail(email);
        SrpRedisEntity srpRedisEntity = srpFlow.beginFlow(A, userEntity);
        BigInteger M1Client = srpFlow.calculateM1Server(srpRedisEntity);
        String M1 = Base64.getEncoder().encodeToString(M1Client.toByteArray());
        LoginCompleteReq req = generateLoginCompleteReq(email, M1);
        String redisKey = RedisKeys.srp(
                userEntity.getUserId().toString(),
                req.getDeviceId().toString()
        );
        redisService.save(
                redisKey,
                srpRedisEntity,
                Duration.of(10, ChronoUnit.SECONDS)
        );
        assertTrue(redisService.exists(redisKey));

        // when
        ResponseEntity<LoginCompleteResp> response = authorizationService.loginUserEnd(req);
        String M2 = Base64.getEncoder().encodeToString(srpFlow.calculateM2Server(srpRedisEntity, M1Client).toByteArray());

        // then
        assertFalse(redisService.exists(redisKey));
        assertEquals(1, auditLogDao.findAll().size());
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(M2, response.getBody().getM2());
        assertArrayEquals(userEntity.getSaltKeyBytes(), response.getBody().getSaltKey());
    }

    @Test
    void shouldSucceedLoginEndWithTotp() throws Exception {
        // given
        String totpSecret = tokenGenerator.generateTotpSecret();
        TotpRedisEntity totpRedisEntity = encryptionService.encryptTotpSecret(totpSecret);
        String A = Base64.getEncoder().encodeToString(BigInteger.TEN.toByteArray());
        UserEntity userEntity = userDao.findByEmail(email);
        TotpEntity totpEntity = generateTotpEntity(
                userEntity,
                totpRedisEntity.getEncryptedTotpSecret(),
                totpRedisEntity.getIv()
        );
        totpDao.save(totpEntity);
        userEntity.setTotpEntity(totpEntity);
        userEntity.setTotpEnabled(true);
        userEntity.setMfaRecoveryCode(UUID.randomUUID().toString());
        userDao.save(userEntity);
        SrpRedisEntity srpRedisEntity = srpFlow.beginFlow(A, userEntity);
        BigInteger M1Client = srpFlow.calculateM1Server(srpRedisEntity);
        String M1 = Base64.getEncoder().encodeToString(M1Client.toByteArray());
        LoginCompleteReq req = generateLoginCompleteReq(email, M1);
        String redisKey = RedisKeys.srp(
                userEntity.getUserId().toString(),
                req.getDeviceId().toString()
        );
        redisService.save(
                redisKey,
                srpRedisEntity,
                Duration.of(10, ChronoUnit.SECONDS)
        );
        assertTrue(redisService.exists(redisKey));

        // when
        ResponseEntity<LoginCompleteResp> response = authorizationService.loginUserEnd(req);
        String M2 = Base64.getEncoder().encodeToString(srpFlow.calculateM2Server(srpRedisEntity, M1Client).toByteArray());

        // then
        assertFalse(redisService.exists(redisKey));
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(M2, response.getBody().getM2());
        String totpCode = response.getBody().getTotpCode();
        String redisTotpLoginKey = RedisKeys.totpLogin(tokenHasher.generateSha256(totpCode));
        assertTrue(redisService.exists(redisTotpLoginKey));
        TotpLoginEntity totpLoginEntity = redisService.get(redisTotpLoginKey, TotpLoginEntity.class);
        assertEquals(totpLoginEntity.getUserId(), userEntity.getUserId());
        assertEquals(totpLoginEntity.getEncryptedTotpSecret(), userEntity.getTotpEntity().getEncryptedToken());
        assertEquals(totpLoginEntity.getTotpIv(), userEntity.getTotpEntity().getTokenIv());
        assertNull(response.getBody().getAccessToken());
        assertNull(response.getBody().getRefreshToken());
    }

    @Test
    void shouldFailTokenNotFoundRefreshJwt() {
        // given
        String token = "token";
        RefreshReq req = generateRefreshReq(token);

        // when
        AuthorizationException ex = assertThrows(
                AuthorizationException.class,
                () -> authorizationService.refreshJWT(req)
        );

        // then
        assertEquals(TOKEN_NOT_FOUND.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_NOT_FOUND.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedRefreshJwt() {
        // given
        String token = "token";
        RefreshReq req = generateRefreshReq(token);
        String tokenHash = tokenHasher.generateSha256(token);
        String redisKey = RedisKeys.session(tokenHash);
        UserEntity userEntity = userDao.findByEmail(email);
        SessionRedisEntity sessionRedisEntity = new SessionRedisEntity(
                userEntity.getUserId(),
                UUID.randomUUID()
        );
        redisService.save(
                redisKey,
                sessionRedisEntity,
                Duration.of(30, ChronoUnit.MINUTES)
        );
        assertTrue(redisService.exists(redisKey));

        // when
        ResponseEntity<RefreshResp> response = authorizationService.refreshJWT(req);

        // then
        assertTrue(redisService.exists(redisKey));
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void shouldFailSessionIsNullLogout() {
        // given
        RefreshReq req = generateRefreshReq("token");

        // when
        AuthorizationException ex = assertThrows(
                AuthorizationException.class,
                () -> authorizationService.logout(req)
        );

        // then
        assertEquals(TOKEN_NOT_FOUND.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_NOT_FOUND.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedLogout() {
        // given
        String token = "token";
        RefreshReq req = generateRefreshReq(token);
        String tokenHash = tokenHasher.generateSha256(token);
        String redisKey = RedisKeys.session(tokenHash);
        UserEntity userEntity = userDao.findByEmail(email);
        SessionRedisEntity sessionRedisEntity = new SessionRedisEntity(
                userEntity.getUserId(),
                UUID.randomUUID()
        );
        redisService.save(
                redisKey,
                sessionRedisEntity,
                Duration.of(30, ChronoUnit.MINUTES)
        );
        assertTrue(redisService.exists(redisKey));

        // when
        ResponseEntity<Void> response = authorizationService.logout(req);

        // then
        assertFalse(redisService.exists(redisKey));
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void shouldFailUserVerificationNotExistsVerifyEmail() {
        // given
        String token = "token";

        // when
        AuthorizationException ex = assertThrows(
                AuthorizationException.class,
                () -> authorizationService.verifyEmail(token)
        );

        // then
        assertEquals(USER_VERIFICATION_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_VERIFICATION_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedVerifyEmail() {
        // given
        String email = "unregistered@gmail.com";
        String token = "token";
        String tokenHash = tokenHasher.generateSha256(token);
        String redisKey = RedisKeys.emailUnverified(tokenHash);
        String emailHash = tokenHasher.generateSha256Email(email);
        String redisKeyEmail = RedisKeys.emailUnverifiedEmail(emailHash);
        UserRedisEntity userRedisEntity = generateUserRedisEntity(
                UUID.randomUUID(),
                email
        );
        redisService.save(
                redisKey,
                userRedisEntity,
                Duration.of(15, ChronoUnit.MINUTES)
        );
        redisService.save(
                redisKeyEmail,
                null,
                Duration.of(15, ChronoUnit.MINUTES)
        );
        assertTrue(redisService.exists(redisKey));
        assertTrue(redisService.exists(redisKeyEmail));
        assertNull(userDao.findByEmail(email));

        // when
        ResponseEntity<String> response = authorizationService.verifyEmail(token);

        // then
        assertFalse(redisService.exists(redisKey));
        assertFalse(redisService.exists(redisKeyEmail));
        assertNotNull(userDao.findByEmail(email));
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

}
