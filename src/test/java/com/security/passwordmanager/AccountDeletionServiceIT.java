package com.security.passwordmanager;

import com.security.passwordmanager.config.EmailClient;
import com.security.passwordmanager.helpers.TokenHasher;
import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.EmailDeletionRedisEntity;
import com.security.passwordmanager.redis.entities.SrpRedisEntity;
import org.junit.jupiter.api.*;
import xyz.segurapass.api.deletion.*;
import com.security.passwordmanager.exceptions.AccountDeletionException;
import com.security.passwordmanager.helpers.EmailService;
import com.security.passwordmanager.helpers.SrpFlow;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.service.AccountDeletionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.math.BigInteger;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static com.security.passwordmanager.exceptions.enums.ErrorEnum.*;
import static com.security.passwordmanager.shared.HelperMethods.*;

@SpringBootTest
public class AccountDeletionServiceIT extends AbstractTestInitializer {

    @Autowired
    private AccountDeletionService accountDeletionService;
    @Autowired
    private UserDao userDao;
    @Autowired
    private SrpFlow srpFlow;
    @Autowired
    private RedisService redisService;
    @Autowired
    private TokenHasher tokenHasher;
    @MockitoBean
    private EmailService emailService;
    @MockitoBean
    private EmailClient emailClient;

    @BeforeEach
    void setup() {
        UserEntity userEntity = generateUserEntity();
        userDao.save(userEntity);
    }

    @AfterEach
    void cleanup() {
        userDao.deleteAll();
        redisService.clearAll();
    }

    @Test
    void shouldFailUserIsNullStartAuthorizedDeletion() {
        // given
        UUID userId = UUID.randomUUID();
        UUID deviceId = UUID.randomUUID();
        AuthorizedDeletionStartReq req = generateAuthorizedDeletionStartReq(deviceId);

        // when
        AccountDeletionException ex = assertThrows(
                AccountDeletionException.class,
                () -> accountDeletionService.startAuthorizedDeletion(userId, req)
        );

        // then
        assertEquals(USER_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedStartAuthorizedDeletion() {
        // given
        UserEntity userEntity = userDao.findByUserId(userId);
        UUID deviceId = UUID.randomUUID();
        AuthorizedDeletionStartReq req = generateAuthorizedDeletionStartReq(deviceId);
        String redisKey = RedisKeys.accountDeletion(userId.toString(), deviceId.toString());
        assertFalse(redisService.exists(redisKey));

        // when
        ResponseEntity<AuthorizedDeletionStartResp> response = accountDeletionService.startAuthorizedDeletion(userId, req);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertArrayEquals(userEntity.getSaltAuthBytes(), response.getBody().getSaltAuth());
        assertTrue(redisService.exists(redisKey));
    }

    @Test
    void shouldFailUserIsNullCompleteAuthorizedDeletion() {
        // given
        UUID userId = UUID.randomUUID();
        UUID deviceId = UUID.randomUUID();
        AuthorizedDeletionCompleteReq req = generateAuthorizedDeletionCompleteReq(deviceId, "randomM1");

        // when
        AccountDeletionException ex = assertThrows(
                AccountDeletionException.class,
                () -> accountDeletionService.completeAuthorizedDeletion(userId, req)
        );

        // then
        assertEquals(USER_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailTokenNotFoundCompleteAuthorizedDeletion() {
        // given
        UUID deviceId = UUID.randomUUID();
        AuthorizedDeletionCompleteReq req = generateAuthorizedDeletionCompleteReq(deviceId, "randomM1");

        // when
        AccountDeletionException ex = assertThrows(
                AccountDeletionException.class,
                () -> accountDeletionService.completeAuthorizedDeletion(userId, req)
        );

        // then
        assertEquals(TOKEN_NOT_FOUND.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_NOT_FOUND.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailM1MismatchCompleteAuthorizedDeletion() {
        // given
        UserEntity userEntity = userDao.findByUserId(userId);
        String A = Base64.getEncoder().encodeToString(BigInteger.TEN.toByteArray());
        SrpRedisEntity srpRedisEntity = srpFlow.beginFlow(A, userEntity);
        UUID deviceId = UUID.randomUUID();
        String redisKey = RedisKeys.accountDeletion(userId.toString(), deviceId.toString());
        redisService.save(
                redisKey,
                srpRedisEntity,
                Duration.of(10, ChronoUnit.SECONDS)
        );
        AuthorizedDeletionCompleteReq req = generateAuthorizedDeletionCompleteReq(deviceId, "randomM1");

        // when
        AccountDeletionException ex = assertThrows(
                AccountDeletionException.class,
                () -> accountDeletionService.completeAuthorizedDeletion(userId, req)
        );

        // then
        assertEquals(SRP_VERIFICATION_FAILED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(SRP_VERIFICATION_FAILED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedCompleteAuthorizedDeletion() {
        // given
        UserEntity userEntity = userDao.findByUserId(userId);
        String A = Base64.getEncoder().encodeToString(BigInteger.TEN.toByteArray());
        SrpRedisEntity srpRedisEntity = srpFlow.beginFlow(A, userEntity);
        String M1 = Base64.getEncoder().encodeToString(srpFlow.calculateM1Server(srpRedisEntity).toByteArray());
        UUID deviceId = UUID.randomUUID();
        String redisKey = RedisKeys.accountDeletion(userId.toString(), deviceId.toString());
        redisService.save(
                redisKey,
                srpRedisEntity,
                Duration.of(10, ChronoUnit.SECONDS)
        );
        AuthorizedDeletionCompleteReq req = generateAuthorizedDeletionCompleteReq(deviceId, M1);
        assertTrue(redisService.exists(redisKey));

        // when
        ResponseEntity<Void> response = accountDeletionService.completeAuthorizedDeletion(userId, req);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNull(userDao.findByUserId(userId));
        assertFalse(redisService.exists(redisKey));
    }

    @Test
    void shouldFailEmailClientNotActiveStartDeletionEmail() {
        // given
        String email = "random@gmail.com";
        EmailDeletionStartReq req = generateEmailDeletionStartReq(email);
        when(emailClient.isActive()).thenReturn(false);

        // when
        AccountDeletionException ex = assertThrows(
                AccountDeletionException.class,
                () -> accountDeletionService.startDeletionEmail(req)
        );

        // then
        assertEquals(EMAIL_VERIFICATION_OFF.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(EMAIL_VERIFICATION_OFF.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailUserIsNullStartDeletionEmail() {
        // given
        String email = "random@gmail.com";
        EmailDeletionStartReq req = generateEmailDeletionStartReq(email);
        when(emailClient.isActive()).thenReturn(true);

        // when
        accountDeletionService.startDeletionEmail(req);

        // then
        verify(emailService, never()).sendDeletionEmail(any(), any());
    }

    @Test
    void shouldFailRedisKeyAlreadyExistsStartDeletionEmail() {
        // given
        EmailDeletionStartReq req = generateEmailDeletionStartReq(email);
        String emailHash = tokenHasher.generateSha256Email(email);
        String redisKey = RedisKeys.emailDeletionEmail(emailHash);
        redisService.save(
                redisKey,
                null,
                Duration.of(15, ChronoUnit.MINUTES)
        );
        assertTrue(redisService.exists(redisKey));
        when(emailClient.isActive()).thenReturn(true);

        // when
        accountDeletionService.startDeletionEmail(req);

        // then
        verify(emailService, never()).sendDeletionEmail(any(), any());
    }

    @Test
    void shouldSucceedStartDeletionEmail() {
        // given
        EmailDeletionStartReq req = generateEmailDeletionStartReq(email);
        String emailHash = tokenHasher.generateSha256Email(email);
        String redisKey = RedisKeys.emailDeletionEmail(emailHash);
        assertFalse(redisService.exists(redisKey));
        when(emailClient.isActive()).thenReturn(true);

        // when
        accountDeletionService.startDeletionEmail(req);

        // then
        assertTrue(redisService.exists(redisKey));
        verify(emailService).sendDeletionEmail(any(), any());
    }

    @Test
    void shouldFailEmailClientNotActiveCompleteDeletionEmail() {
        // given
        String token = UUID.randomUUID().toString();
        when(emailClient.isActive()).thenReturn(false);

        // when
        AccountDeletionException ex = assertThrows(
                AccountDeletionException.class,
                () -> accountDeletionService.completeDeletionEmail(token)
        );

        // then
        assertEquals(EMAIL_VERIFICATION_OFF.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(EMAIL_VERIFICATION_OFF.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailTokenNotFoundCompleteDeletionEmail() {
        // given
        String token = UUID.randomUUID().toString();
        when(emailClient.isActive()).thenReturn(true);

        // when
        AccountDeletionException ex = assertThrows(
                AccountDeletionException.class,
                () -> accountDeletionService.completeDeletionEmail(token)
        );

        // then
        assertEquals(TOKEN_NOT_FOUND.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_NOT_FOUND.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedCompleteDeletionEmail() {
        // given
        String token = UUID.randomUUID().toString();
        String redisKey = RedisKeys.emailDeletion(tokenHasher.generateSha256(token));
        String emailHash = tokenHasher.generateSha256Email(token);
        EmailDeletionRedisEntity emailDeletionRedisEntity = new EmailDeletionRedisEntity(userId, emailHash);
        redisService.save(
                redisKey,
                emailDeletionRedisEntity,
                Duration.of(15, ChronoUnit.MINUTES)
        );
        String emailHashRedisKey = RedisKeys.emailDeletionEmail(emailHash);
        redisService.save(
                emailHashRedisKey,
                null,
                Duration.of(15, ChronoUnit.MINUTES)
        );
        assertTrue(redisService.exists(redisKey));
        assertTrue(redisService.exists(emailHashRedisKey));
        when(emailClient.isActive()).thenReturn(true);

        // when
        ResponseEntity<String> response = accountDeletionService.completeDeletionEmail(token);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNull(userDao.findByUserId(userId));
        assertFalse(redisService.exists(redisKey));
        assertFalse(redisService.exists(emailHashRedisKey));
    }

}
