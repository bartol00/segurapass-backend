package com.security.passwordmanager;

import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.SrpRedisEntity;
import org.junit.jupiter.api.*;
import xyz.segurapass.api.deletion.*;
import com.security.passwordmanager.exceptions.AccountDeletionException;
import com.security.passwordmanager.helpers.EmailService;
import com.security.passwordmanager.helpers.SrpFlow;
import com.security.passwordmanager.helpers.TokenHasher;
import com.security.passwordmanager.model.authorization.SrpEntity;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.deletion.EmailDeletionDao;
import com.security.passwordmanager.model.deletion.EmailDeletionEntity;
import com.security.passwordmanager.service.AccountDeletionService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

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
public class AccountDeletionServiceTest extends AbstractTestInitializer {

    private final String email = "me@gmail.com";
    private final String token = "random token";
    private final String authorizedEmail = "authorized@gmail.com";
    private final UUID authorizedDeviceId = UUID.fromString("9a55c43b-52b3-4efb-b77c-3747b115e551");
    private final UUID userId = UUID.fromString("14bd3b93-3413-4108-a68b-416cb71e6c70");
    private final UUID authorizedUserId = UUID.fromString("decc9437-bf41-403c-9ee4-d3f9c308115a");

    @Autowired
    private AccountDeletionService accountDeletionService;
    @Autowired
    private TokenHasher tokenHasher;
    @MockitoSpyBean
    private UserDao userDao;
    @MockitoSpyBean
    private EmailDeletionDao emailDeletionDao;
    @MockitoSpyBean
    private SrpFlow srpFlow;
    @MockitoBean
    private EmailService emailService;
    @MockitoSpyBean
    private RedisService redisService;

    @BeforeEach
    void setup() {
        UserEntity userEntity = generateUserEntity(userId);
        userEntity = userDao.save(userEntity);
        EmailDeletionEntity emailDeletionEntity = generateEmailDeletionEntity();
        emailDeletionEntity.setUserEntity(userEntity);
        emailDeletionDao.save(emailDeletionEntity);
        UserEntity authorizedUser = generateUserEntity(authorizedUserId);
        authorizedUser.setEmail(authorizedEmail);
        authorizedUser.setVerifier("authorizedVerifier");
        userDao.save(authorizedUser);
    }

    @AfterEach
    void cleanup() {
        userDao.deleteAll();
    }

    @Test
    void shouldFailUserIsNullStartAuthorizedDeletion() {
        // given
        UUID randomUserId = UUID.randomUUID();
        AuthorizedDeletionStartReq req = generateAuthorizedDeletionStartReq();

        // when
        AccountDeletionException ex = assertThrows(AccountDeletionException.class, () -> accountDeletionService.startAuthorizedDeletion(randomUserId, req));

        // then
        assertEquals(USER_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedStartAuthorizedDeletion() {
        // given
        UserEntity userEntity = userDao.findByEmail(authorizedEmail);
        AuthorizedDeletionStartReq req = generateAuthorizedDeletionStartReq();

        // when
        ResponseEntity<AuthorizedDeletionStartResp> response = accountDeletionService.startAuthorizedDeletion(authorizedUserId, req);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userEntity.getSaltAuth(), response.getBody().getSaltAuth());
    }

    @Test
    void shouldFailUserNotExistsAuthorizedDeletion() {
        // given
        AuthorizedDeletionCompleteReq req = generateAuthorizedDeletionCompleteReq();
        doReturn(null).when(userDao).findByUserId(authorizedUserId);

        // when
        AccountDeletionException ex = assertThrows(AccountDeletionException.class, () -> accountDeletionService.completeAuthorizedDeletion(authorizedUserId, req));

        // then
        assertEquals(USER_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailTokenExpiredCompleteAuthorizedDeletion() {
        // given
        AuthorizedDeletionCompleteReq req = generateAuthorizedDeletionCompleteReq();
        String userIdString = authorizedUserId.toString();
        String deviceIdString = req.getDeviceId().toString();
        String redisKey = "segurapass:srp:" + userIdString + ":" + deviceIdString;
        doReturn(false).when(redisService).exists(redisKey);

        // when
        AccountDeletionException ex = assertThrows(AccountDeletionException.class, () -> accountDeletionService.completeAuthorizedDeletion(authorizedUserId, req));

        // then
        assertEquals(TOKEN_EXPIRED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_EXPIRED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailM1MismatchCompleteAuthorizedDeletion() {
        // given
        AuthorizedDeletionCompleteReq req = generateAuthorizedDeletionCompleteReq();

        // when
        AccountDeletionException ex = assertThrows(AccountDeletionException.class, () -> accountDeletionService.completeAuthorizedDeletion(authorizedUserId, req));

        // then
        assertEquals(SRP_VERIFICATION_FAILED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(SRP_VERIFICATION_FAILED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedCompleteAuthorizedDeletion() {
        // given
        AuthorizedDeletionCompleteReq req = generateAuthorizedDeletionCompleteReq();
        String userIdString = authorizedUserId.toString();
        String deviceIdString = req.getDeviceId().toString();
        String redisKey = "segurapass:srp:" + userIdString + ":" + deviceIdString;
        doReturn(true).when(redisService).exists(redisKey);
        doReturn(new SrpRedisEntity()).when(redisService).get(redisKey, SrpRedisEntity.class);
        doReturn(new BigInteger(1, Base64.getDecoder().decode(req.getM1()))).when(srpFlow).calculateM1Server(any(SrpRedisEntity.class));
        doNothing().when(userDao).deleteByUserId(authorizedUserId);

        // when
        ResponseEntity<Void> response = accountDeletionService.completeAuthorizedDeletion(authorizedUserId, req);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void shouldFailUserIsNullStartDeletionEmail() {
        // given
        String randomEmail = "random@gmail.com";
        EmailDeletionStartReq req = generateEmailDeletionStartReq();
        req.setEmail(randomEmail);

        // when
        accountDeletionService.startDeletionEmail(req);

        // then
        assertFalse(emailDeletionDao.existsByUserEntity_Email(randomEmail));
    }

    @Test
    void shouldFailEmailEntityAlreadyExistsStartDeletionEmail() {
        // given
        EmailDeletionStartReq req = generateEmailDeletionStartReq();
        EmailDeletionEntity emailDeletionEntity = emailDeletionDao.findByUserEntity_Email(email);

        // when
        accountDeletionService.startDeletionEmail(req);
        EmailDeletionEntity retrievedEntity = emailDeletionDao.findByUserEntity_Email(email);

        // then
        assertEquals(emailDeletionEntity.getToken(), retrievedEntity.getToken());
        assertEquals(emailDeletionEntity.getId(), retrievedEntity.getId());
    }

    @Test
    void shouldSucceedStartDeletionEmail() {
        // given
        String testEmail = "test@gmail.com";
        EmailDeletionStartReq req = generateEmailDeletionStartReq();
        req.setEmail(testEmail);
        UserEntity userEntity = generateUserEntity(UUID.randomUUID());
        userEntity.setEmail(testEmail);
        userDao.save(userEntity);

        // when
        accountDeletionService.startDeletionEmail(req);

        // then
        assertTrue(emailDeletionDao.existsByUserEntity_Email(testEmail));
    }

    @Test
    void shouldFailMissingTokenCompleteDeletionEmail() {
        // given
        String randomToken = UUID.randomUUID().toString();

        // when
        AccountDeletionException ex = assertThrows(AccountDeletionException.class, () -> accountDeletionService.completeDeletionEmail(randomToken));

        // then
        assertEquals(USER_DELETION_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_DELETION_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailExpiredTokenCompleteDeletionEmail() {
        // given
        EmailDeletionEntity emailDeletionEntity = emailDeletionDao.findByUserEntity_Email(email);
        emailDeletionEntity.setTokenExpiry(Instant.now().minus(2, ChronoUnit.MINUTES));
        emailDeletionDao.save(emailDeletionEntity);

        // when
        AccountDeletionException ex = assertThrows(AccountDeletionException.class, () -> accountDeletionService.completeDeletionEmail(token));

        // then
        assertEquals(USER_DELETION_EXPIRED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_DELETION_EXPIRED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedCompleteDeletionEmail() {
        // given
        EmailDeletionEntity emailDeletionEntity = emailDeletionDao.findByUserEntity_Email(email);
        emailDeletionEntity.setTokenExpiry(Instant.now().plus(2, ChronoUnit.MINUTES));
        emailDeletionDao.save(emailDeletionEntity);

        // when
        ResponseEntity<String> response = accountDeletionService.completeDeletionEmail(token);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertFalse(userDao.existsByEmail(email));
        assertFalse(emailDeletionDao.existsByUserEntity_Email(email));
    }


    private AuthorizedDeletionStartReq generateAuthorizedDeletionStartReq() {
        AuthorizedDeletionStartReq authorizedDeletionStartReq = new AuthorizedDeletionStartReq();
        authorizedDeletionStartReq.setDeviceId(authorizedDeviceId);
        authorizedDeletionStartReq.setA("publicA");
        return authorizedDeletionStartReq;
    }

    private AuthorizedDeletionCompleteReq generateAuthorizedDeletionCompleteReq() {
        AuthorizedDeletionCompleteReq authorizedDeletionCompleteReq = new AuthorizedDeletionCompleteReq();
        authorizedDeletionCompleteReq.setDeviceId(authorizedDeviceId);
        authorizedDeletionCompleteReq.setM1("clientM1");
        return authorizedDeletionCompleteReq;
    }

    private EmailDeletionStartReq generateEmailDeletionStartReq() {
        EmailDeletionStartReq emailDeletionStartReq = new EmailDeletionStartReq();
        emailDeletionStartReq.setEmail(email);
        return emailDeletionStartReq;
    }

    private UserEntity generateUserEntity(UUID userId) {
        UserEntity userEntity = new UserEntity();
        userEntity.setUserId(userId);
        userEntity.setEmail(email);
        userEntity.setSaltAuth(UUID.randomUUID().toString());
        userEntity.setVerifier(UUID.randomUUID().toString());
        userEntity.setSaltKey(UUID.randomUUID().toString());
        userEntity.setEmailVerified(true);
        return userEntity;
    }

    private EmailDeletionEntity generateEmailDeletionEntity() {
        EmailDeletionEntity emailDeletionEntity = new EmailDeletionEntity();
        emailDeletionEntity.setToken(tokenHasher.generateSha256(token));
        emailDeletionEntity.setTokenExpiry(Instant.now());
        return emailDeletionEntity;
    }

    private SrpEntity generateSrpEntity() {
        SrpEntity srpEntity = new SrpEntity();
        srpEntity.setId(1L);
        srpEntity.setA("publicA");
        srpEntity.setBpriv("privateB");
        srpEntity.setB("publicB");
        srpEntity.setVerifier("verifier");
        srpEntity.setDeviceId(UUID.randomUUID());
        srpEntity.setUserEntity(userDao.findByEmail(authorizedEmail));
        srpEntity.setExpiryTime(Instant.now().plus(30, ChronoUnit.MINUTES));
        return srpEntity;
    }

}
