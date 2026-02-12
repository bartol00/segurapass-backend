package com.security.passwordmanager;

import com.security.passwordmanager.api.deletion.AuthorizedDeletionCompleteReq;
import com.security.passwordmanager.api.deletion.AuthorizedDeletionStartReq;
import com.security.passwordmanager.api.deletion.AuthorizedDeletionStartResp;
import com.security.passwordmanager.api.deletion.EmailDeletionStartReq;
import com.security.passwordmanager.api.error.ApiError;
import com.security.passwordmanager.api.error.ApiErrorEnum;
import com.security.passwordmanager.helpers.EmailService;
import com.security.passwordmanager.helpers.SrpFlow;
import com.security.passwordmanager.helpers.TokenHasher;
import com.security.passwordmanager.model.authorization.SrpDao;
import com.security.passwordmanager.model.authorization.SrpEntity;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.deletion.EmailDeletionDao;
import com.security.passwordmanager.model.deletion.EmailDeletionEntity;
import com.security.passwordmanager.service.AccountDeletionService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

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
public class AccountDeletionServiceIT extends AbstractPostgresIT {

    private final String email = "me@gmail.com";
    private final String token = "random token";
    private final String authorizedEmail = "authorized@gmail.com";
    private final UUID authorizedDeviceId = UUID.fromString("9a55c43b-52b3-4efb-b77c-3747b115e551");


    @Autowired
    private AccountDeletionService accountDeletionService;
    @Autowired
    private TokenHasher tokenHasher;
    @MockitoSpyBean
    private UserDao userDao;
    @MockitoSpyBean
    private EmailDeletionDao emailDeletionDao;
    @MockitoSpyBean
    private SrpDao srpDao;
    @MockitoSpyBean
    private SrpFlow srpFlow;
    @MockitoBean
    private EmailService emailService;

    @BeforeAll
    void setup() {
        userDao.deleteAll();
        UserEntity userEntity = generateUserEntity();
        userEntity = userDao.save(userEntity);
        EmailDeletionEntity emailDeletionEntity = generateEmailDeletionEntity();
        emailDeletionEntity.setUserEntity(userEntity);
        emailDeletionDao.save(emailDeletionEntity);
        UserEntity authorizedUser = generateUserEntity();
        authorizedUser.setEmail(authorizedEmail);
        authorizedUser.setVerifier("authorizedVerifier");
        userDao.save(authorizedUser);
    }

    @Test
    void shouldFailUserIsNullStartAuthorizedDeletion() {
        // given
        String randomEmail = "random@gmail.com";
        AuthorizedDeletionStartReq authorizedDeletionStartReq = generateAuthorizedDeletionStartReq();

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) accountDeletionService.startAuthorizedDeletion(randomEmail, authorizedDeletionStartReq);

        // then
        assertEquals(ApiErrorEnum.USER_NOT_EXISTS.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.USER_NOT_EXISTS.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldSucceedStartAuthorizedDeletion() {
        // given
        UserEntity userEntity = userDao.findByEmail(authorizedEmail);
        AuthorizedDeletionStartReq authorizedDeletionStartReq = generateAuthorizedDeletionStartReq();

        // when
        ResponseEntity<AuthorizedDeletionStartResp> response = (ResponseEntity<AuthorizedDeletionStartResp>) accountDeletionService.startAuthorizedDeletion(authorizedEmail, authorizedDeletionStartReq);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userEntity.getSaltAuth(), response.getBody().getSaltAuth());
    }

    @Test
    void shouldFailSrpIsNullCompleteAuthorizedDeletion() {
        // given
        doReturn(null).when(srpDao).findByUserEntity_EmailAndDeviceId(authorizedEmail, authorizedDeviceId);
        AuthorizedDeletionCompleteReq authorizedDeletionCompleteReq = generateAuthorizedDeletionCompleteReq();

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) accountDeletionService.completeAuthorizedDeletion(authorizedEmail, authorizedDeletionCompleteReq);

        // then
        assertEquals(ApiErrorEnum.SRP_SESSION_NOT_FOUND.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.SRP_SESSION_NOT_FOUND.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldFailSrpIsExpiredCompleteAuthorizedDeletion() {
        // given
        SrpEntity srpEntity = generateSrpEntity();
        srpEntity.setExpiryTime(Instant.now().minus(1, ChronoUnit.MINUTES));
        AuthorizedDeletionCompleteReq authorizedDeletionCompleteReq = generateAuthorizedDeletionCompleteReq();
        doReturn(srpEntity).when(srpDao).findByUserEntity_EmailAndDeviceId(authorizedEmail, authorizedDeviceId);
        doNothing().when(srpDao).delete(srpEntity);

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) accountDeletionService.completeAuthorizedDeletion(authorizedEmail, authorizedDeletionCompleteReq);

        // then
        assertEquals(ApiErrorEnum.SRP_SESSION_EXPIRED.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.SRP_SESSION_EXPIRED.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldFailM1MismatchCompleteAuthorizedDeletion() {
        // given
        SrpEntity srpEntity = generateSrpEntity();
        AuthorizedDeletionCompleteReq authorizedDeletionCompleteReq = generateAuthorizedDeletionCompleteReq();
        doReturn(srpEntity).when(srpDao).findByUserEntity_EmailAndDeviceId(authorizedEmail, authorizedDeviceId);
        doNothing().when(srpDao).delete(srpEntity);

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) accountDeletionService.completeAuthorizedDeletion(authorizedEmail, authorizedDeletionCompleteReq);

        // then
        assertEquals(ApiErrorEnum.SRP_VERIFICATION_FAILED.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.SRP_VERIFICATION_FAILED.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldSucceedCompleteAuthorizedDeletion() {
        // given
        SrpEntity srpEntity = generateSrpEntity();
        AuthorizedDeletionCompleteReq authorizedDeletionCompleteReq = generateAuthorizedDeletionCompleteReq();
        doReturn(srpEntity).when(srpDao).findByUserEntity_EmailAndDeviceId(authorizedEmail, authorizedDeviceId);
        doNothing().when(srpDao).delete(srpEntity);
        doReturn(new BigInteger(1, Base64.getDecoder().decode(authorizedDeletionCompleteReq.getM1()))).when(srpFlow).calculateM1Server(srpEntity);
        doNothing().when(userDao).deleteByEmail(authorizedEmail);

        // when
        ResponseEntity<?> response = accountDeletionService.completeAuthorizedDeletion(authorizedEmail, authorizedDeletionCompleteReq);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void shouldFailUserIsNullStartDeletionEmail() {
        // given
        String randomEmail = "random@gmail.com";
        EmailDeletionStartReq emailDeletionStartReq = generateEmailDeletionStartReq();
        emailDeletionStartReq.setEmail(randomEmail);

        // when
        accountDeletionService.startDeletionEmail(emailDeletionStartReq);

        // then
        assertFalse(emailDeletionDao.existsByUserEntity_Email(randomEmail));
    }

    @Test
    void shouldFailEmailEntityAlreadyExistsStartDeletionEmail() {
        // given
        EmailDeletionStartReq emailDeletionStartReq = generateEmailDeletionStartReq();
        EmailDeletionEntity emailDeletionEntity = emailDeletionDao.findByUserEntity_Email(email);

        // when
        accountDeletionService.startDeletionEmail(emailDeletionStartReq);
        EmailDeletionEntity retrievedEntity = emailDeletionDao.findByUserEntity_Email(email);

        // then
        assertEquals(emailDeletionEntity.getToken(), retrievedEntity.getToken());
        assertEquals(emailDeletionEntity.getId(), retrievedEntity.getId());
    }

    @Test
    void shouldSucceedStartDeletionEmail() {
        // given
        String testEmail = "test@gmail.com";
        EmailDeletionStartReq emailDeletionStartReq = generateEmailDeletionStartReq();
        emailDeletionStartReq.setEmail(testEmail);
        UserEntity userEntity = generateUserEntity();
        userEntity.setEmail(testEmail);
        userDao.save(userEntity);

        // when
        accountDeletionService.startDeletionEmail(emailDeletionStartReq);

        // then
        assertTrue(emailDeletionDao.existsByUserEntity_Email(testEmail));
    }

    @Test
    void shouldFailMissingTokenCompleteDeletionEmail() {
        // given
        String randomToken = UUID.randomUUID().toString();

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) accountDeletionService.completeDeletionEmail(randomToken);

        // then
        assertEquals(ApiErrorEnum.USER_DELETION_NOT_EXISTS.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.USER_DELETION_NOT_EXISTS.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldFailExpiredTokenCompleteDeletionEmail() {
        // given
        EmailDeletionEntity emailDeletionEntity = emailDeletionDao.findByUserEntity_Email(email);
        emailDeletionEntity.setTokenExpiry(Instant.now().minus(2, ChronoUnit.MINUTES));
        emailDeletionDao.save(emailDeletionEntity);

        // when
        ResponseEntity<ApiError> response = (ResponseEntity<ApiError>) accountDeletionService.completeDeletionEmail(token);

        // then
        assertEquals(ApiErrorEnum.USER_DELETION_EXPIRED.getHttpStatus(), response.getStatusCode());
        assertEquals(ApiErrorEnum.USER_DELETION_EXPIRED.getMessage(), response.getBody().getMessage());
    }

    @Test
    void shouldSucceedCompleteDeletionEmail() {
        // given
        EmailDeletionEntity emailDeletionEntity = emailDeletionDao.findByUserEntity_Email(email);
        emailDeletionEntity.setTokenExpiry(Instant.now().plus(2, ChronoUnit.MINUTES));
        emailDeletionDao.save(emailDeletionEntity);

        // when
        ResponseEntity<?> response = accountDeletionService.completeDeletionEmail(token);

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

    private UserEntity generateUserEntity() {
        UserEntity userEntity = new UserEntity();
        userEntity.setUserId(UUID.randomUUID());
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
