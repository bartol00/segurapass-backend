package com.security.passwordmanager;

import com.security.passwordmanager.model.audit.AuditLogDao;
import org.junit.jupiter.api.*;
import xyz.segurapass.api.credentials.*;
import com.security.passwordmanager.exceptions.CredentialsException;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.credentials.CredentialsDao;
import com.security.passwordmanager.model.credentials.CredentialsEntity;
import com.security.passwordmanager.service.CredentialsService;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static com.security.passwordmanager.exceptions.ErrorEnum.*;
import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@SpringBootTest
public class CredentialsServiceTest extends AbstractTestInitializer {

    private final UUID userId = UUID.fromString("14bd3b93-3413-4108-a68b-416cb71e6c70");

    @Autowired
    private CredentialsService credentialsService;
    @Autowired
    private UserDao userDao;
    @Autowired
    private CredentialsDao credentialsDao;
    @Autowired
    private AuditLogDao auditLogDao;

    @BeforeEach
    void setup() {
        MDC.put("clientIp", "127.0.0.1");

        UserEntity userEntity = generateUserEntity(userId);
        userDao.save(userEntity);

        CredentialsEntity credentialsEntity1 = generateCredentialsEntity(userEntity);
        CredentialsEntity credentialsEntity2 = generateCredentialsEntity(userEntity);
        CredentialsEntity credentialsEntity3 = generateCredentialsEntity(userEntity);
        List<CredentialsEntity> credentialsEntityList = List.of(credentialsEntity1, credentialsEntity2, credentialsEntity3);
        credentialsDao.saveAll(credentialsEntityList);
    }

    @AfterEach
    void clean() {
        credentialsDao.deleteAll();
        userDao.deleteAll();
        auditLogDao.deleteAll();
        MDC.clear();
    }

    @Test
    void shouldSucceedGetCredentials() {
        // when
        ResponseEntity<Page<CredentialsResp>> response = credentialsService.getCredentials(userId, 0, 20);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(3, response.getBody().getTotalElements());
    }

    @Test
    void shouldFailCredentialIsNullGetCredentialById() {
        // given
        UUID credentialsId = UUID.randomUUID();

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.getCredentialById(credentialsId, userId)
        );

        // then
        assertEquals(CREDENTIAL_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(CREDENTIAL_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedGetCredentialById() {
        // given
        List<CredentialsEntity> credentialsEntityList = credentialsDao.findAll();
        CredentialsEntity credentialsEntity = credentialsEntityList.getFirst();

        // when
        ResponseEntity<CredentialsResp> response = credentialsService.getCredentialById(
                credentialsEntity.getCredentialsId(),
                userId
        );
        CredentialsResp resp = response.getBody();

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(resp);
        assertEquals(resp.getCredentialsId(), credentialsEntity.getCredentialsId());
        assertEquals(resp.getWebsite(), credentialsEntity.getWebsite());
        assertEquals(resp.getIvWebsite(), credentialsEntity.getIvWebsite());
    }

    @Test
    void shouldSucceedCreateCredentials() {
        // given
        CredentialsReq req = generateCredentialsReq();
        long count = credentialsDao.count();

        // when
        ResponseEntity<CredentialsResp> response = credentialsService.createCredentials(req, userId);
        CredentialsResp resp = response.getBody();

        // then
        assertEquals(count + 1, credentialsDao.count());
        assertEquals(1, auditLogDao.findAll().size());
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(resp);
        assertEquals(resp.getWebsite(), req.getWebsite());
        assertEquals(resp.getIvWebsite(), req.getIvWebsite());
    }

    @Test
    void shouldFailCredentialIsNullUpdateCredentials() {
        // given
        UUID credentialsId = UUID.randomUUID();
        CredentialsReq req = generateCredentialsReq();

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.updateCredentials(credentialsId, req, userId)
        );

        // then
        assertEquals(CREDENTIAL_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(CREDENTIAL_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailMissingIvUpdateCredentials() {
        // given
        List<CredentialsEntity> credentialsEntityList = credentialsDao.findAll();
        CredentialsEntity credentialsEntity = credentialsEntityList.getFirst();
        UUID credentialsId = credentialsEntity.getCredentialsId();
        CredentialsReq req = generateCredentialsReq();
        req.setIvWebsite(null);

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.updateCredentials(credentialsId, req, userId)
        );

        // then
        assertEquals(CREDENTIAL_UPDATE_IV_MISSING.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(CREDENTIAL_UPDATE_IV_MISSING.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedUpdateCredentials() {
        // given
        List<CredentialsEntity> credentialsEntityList = credentialsDao.findAll();
        CredentialsEntity credentialsEntity = credentialsEntityList.getFirst();
        UUID credentialsId = credentialsEntity.getCredentialsId();
        CredentialsReq req = generateCredentialsReq();

        // when
        ResponseEntity<CredentialsResp> response = credentialsService.updateCredentials(credentialsId, req, userId);
        CredentialsResp resp = response.getBody();

        // then
        assertEquals(1, auditLogDao.findAll().size());
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(resp);
        assertNotEquals(credentialsEntity.getIvWebsite(), resp.getIvWebsite());
        assertNotEquals(credentialsEntity.getIvUsername(), resp.getIvUsername());
        assertNotEquals(credentialsEntity.getIvPassword(), resp.getIvUsername());
    }

    @Test
    void shouldFailCredentialIsNullDeleteCredentials() {
        // given
        UUID credentialsId = UUID.randomUUID();

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.deleteCredentials(credentialsId, userId)
        );

        // then
        assertEquals(CREDENTIAL_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(CREDENTIAL_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedDeleteCredentials() {
        // given
        List<CredentialsEntity> credentialsEntityList = credentialsDao.findAll();
        CredentialsEntity credentialsEntity = credentialsEntityList.getFirst();
        UUID credentialsId = credentialsEntity.getCredentialsId();
        long count = credentialsDao.count();

        // when
        ResponseEntity<Void> response = credentialsService.deleteCredentials(credentialsId, userId);

        // then
        assertEquals(1, auditLogDao.findAll().size());
        assertEquals(count - 1, credentialsDao.count());
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(credentialsDao.findById(credentialsEntity.getId()).isEmpty());
    }

    private CredentialsReq generateCredentialsReq() {
        CredentialsReq credentialsReq = new CredentialsReq();
        credentialsReq.setWebsite("unique website");
        credentialsReq.setUsername("unique username");
        credentialsReq.setPassword("unique password");
        credentialsReq.setIvWebsite(UUID.randomUUID().toString());
        credentialsReq.setIvUsername(UUID.randomUUID().toString());
        credentialsReq.setIvPassword(UUID.randomUUID().toString());
        return credentialsReq;
    }

    private UserEntity generateUserEntity(UUID userId) {
        UserEntity userEntity = new UserEntity();
        userEntity.setUserId(userId);
        userEntity.setEmail("user@gmail.com");
        userEntity.setSaltAuth("saltAuth");
        userEntity.setVerifier("verifier");
        userEntity.setSaltKey("saltKey");
        return userEntity;
    }

    private CredentialsEntity generateCredentialsEntity(UserEntity userEntity) {
        CredentialsEntity credentialsEntity = new CredentialsEntity();
        credentialsEntity.setCredentialsId(UUID.randomUUID());
        credentialsEntity.setWebsite(UUID.randomUUID().toString());
        credentialsEntity.setUsername(UUID.randomUUID().toString());
        credentialsEntity.setPassword(UUID.randomUUID().toString());
        credentialsEntity.setIvWebsite(UUID.randomUUID().toString());
        credentialsEntity.setIvUsername(UUID.randomUUID().toString());
        credentialsEntity.setIvPassword(UUID.randomUUID().toString());
        credentialsEntity.setLastUpdated(Instant.now());
        credentialsEntity.setUserEntity(userEntity);
        return credentialsEntity;
    }

}
