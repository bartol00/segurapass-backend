package com.security.passwordmanager;

import com.security.passwordmanager.api.deletion.EmailDeletionStartReq;
import com.security.passwordmanager.api.error.ApiError;
import com.security.passwordmanager.api.error.ApiErrorEnum;
import com.security.passwordmanager.helpers.EmailService;
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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@SpringBootTest
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class AccountDeletionServiceIT {

    private final String email = "me@gmail.com";

    @Autowired
    private AccountDeletionService accountDeletionService;
    @MockitoSpyBean
    private UserDao userDao;
    @MockitoSpyBean
    private EmailDeletionDao emailDeletionDao;
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
        String token = emailDeletionEntity.getToken();

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
        String token = emailDeletionEntity.getToken();

        // when
        ResponseEntity<?> response = accountDeletionService.completeDeletionEmail(token);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertFalse(userDao.existsByEmail(email));
        assertFalse(emailDeletionDao.existsByUserEntity_Email(email));
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
        emailDeletionEntity.setToken(UUID.randomUUID().toString());
        emailDeletionEntity.setTokenExpiry(Instant.now());
        return emailDeletionEntity;
    }

}
