package com.security.passwordmanager;

import xyz.segurapass.api.credentials.*;
import com.security.passwordmanager.exceptions.CredentialsException;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.credentials.CredentialsDao;
import com.security.passwordmanager.model.credentials.CredentialsEntity;
import com.security.passwordmanager.service.CredentialsService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static com.security.passwordmanager.exceptions.ErrorEnum.*;
import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class CredentialsServiceIT extends AbstractTestInitializer {

    private final String email = "me@gmail.com";
    private final UUID userId = UUID.fromString("5aef2ede-f0f1-487f-af5a-00a455f49a30");

    @Autowired
    private CredentialsService credentialsService;
    @MockitoSpyBean
    private UserDao userDao;
    @MockitoSpyBean
    private CredentialsDao credentialsDao;

    @BeforeAll
    void setup() {
        userDao.deleteAll();

        UserEntity userEntity = generateUserEntity();
        userDao.save(userEntity);

        CredentialsEntity credentialsEntity1 = generateCredentialsEntity();
        credentialsEntity1.setUserEntity(userEntity);
        CredentialsEntity credentialsEntity2 = generateCredentialsEntity();
        credentialsEntity2.setUserEntity(userEntity);
        CredentialsEntity credentialsEntity3 = generateCredentialsEntity();
        credentialsEntity3.setUserEntity(userEntity);
        List<CredentialsEntity> credentialsEntityList = List.of(credentialsEntity1, credentialsEntity2, credentialsEntity3);
        credentialsDao.saveAll(credentialsEntityList);
    }

    @AfterAll
    void clean() {
        credentialsDao.deleteAll();
        userDao.deleteAll();
    }


    @Test
    void shouldSucceedGetCredentials() {
        // when
        ResponseEntity<Page<CredentialsResp>> response = credentialsService.getCredentials(userId, 0, 20);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(3, response.getBody().getTotalElements());
    }

    @Test
    void shouldFailCredentialIsNullGetCredentialById() {
        // given
        UUID idToFind = UUID.randomUUID();

        // when
        CredentialsException ex = assertThrows(CredentialsException.class, () -> credentialsService.getCredentialById(idToFind, userId));

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
        ResponseEntity<CredentialsResp> response = credentialsService.getCredentialById(credentialsEntity.getCredentialsId(), userId);
        CredentialsResp resp = response.getBody();

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(resp.getCredentialsId(), credentialsEntity.getCredentialsId());
        assertEquals(resp.getWebsite(), credentialsEntity.getWebsite());
        assertEquals(resp.getIvWebsite(), credentialsEntity.getIvWebsite());
    }

    @Test
    void shouldSucceedCreateCredentials() {
        // given
        MDC.put("clientIp", "127.0.0.1");
        CredentialsReq req = generateCredentialsReq();
        long count = credentialsDao.count();

        // when
        ResponseEntity<CredentialsResp> response = credentialsService.createCredentials(req, userId);
        CredentialsResp resp = response.getBody();

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(count + 1, credentialsDao.count());
        assertEquals(resp.getWebsite(), req.getWebsite());
        assertEquals(resp.getIvWebsite(), req.getIvWebsite());

        MDC.clear();
    }

    @Test
    void shouldFailCredentialIsNullUpdateCredentials() {
        // given
        UUID idToFind = UUID.randomUUID();
        CredentialsReq req = generateCredentialsReq();

        // when
        CredentialsException ex = assertThrows(CredentialsException.class, () -> credentialsService.updateCredentials(idToFind, req, userId));

        // then
        assertEquals(CREDENTIAL_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(CREDENTIAL_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailMissingIvUpdateCredentials() {
        // given
        List<CredentialsEntity> credentialsEntityList = credentialsDao.findAll();
        CredentialsEntity credentialsEntity = credentialsEntityList.getFirst();
        CredentialsReq req = generateCredentialsReq();
        req.setIvWebsite(null);

        // when
        CredentialsException ex = assertThrows(CredentialsException.class, () -> credentialsService.updateCredentials(credentialsEntity.getCredentialsId(), req, userId));

        // then
        assertEquals(CREDENTIAL_UPDATE_IV_MISSING.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(CREDENTIAL_UPDATE_IV_MISSING.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedUpdateCredentials() {
        // given
        MDC.put("clientIp", "127.0.0.1");
        List<CredentialsEntity> credentialsEntityList = credentialsDao.findAll();
        CredentialsEntity credentialsEntity = credentialsEntityList.getFirst();
        CredentialsReq req = generateCredentialsReq();

        // when
        ResponseEntity<CredentialsResp> response = credentialsService.updateCredentials(credentialsEntity.getCredentialsId(), req, userId);
        CredentialsResp resp = response.getBody();

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotEquals(credentialsEntity.getIvWebsite(), resp.getIvWebsite());
        assertNotEquals(credentialsEntity.getIvUsername(), resp.getIvUsername());
        assertNotEquals(credentialsEntity.getIvPassword(), resp.getIvUsername());

        MDC.clear();
    }

    @Test
    void shouldFailCredentialIsNullDeleteCredentials() {
        // given
        UUID idToFind = UUID.randomUUID();

        // when
        CredentialsException ex = assertThrows(CredentialsException.class, () -> credentialsService.deleteCredentials(idToFind, userId));

        // then
        assertEquals(CREDENTIAL_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(CREDENTIAL_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedDeleteCredentials() {
        // given
        MDC.put("clientIp", "127.0.0.1");
        List<CredentialsEntity> credentialsEntityList = credentialsDao.findAll();
        CredentialsEntity credentialsEntity = credentialsEntityList.getFirst();
        long count = credentialsDao.count();

        // when
        ResponseEntity<Void> response = credentialsService.deleteCredentials(credentialsEntity.getCredentialsId(), userId);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(count - 1, credentialsDao.count());
        assertTrue(credentialsDao.findById(credentialsEntity.getId()).isEmpty());

        MDC.clear();
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

    private UserEntity generateUserEntity() {
        UserEntity userEntity = new UserEntity();
        userEntity.setUserId(userId);
        userEntity.setEmail(email);
        userEntity.setSaltAuth("saltAuth");
        userEntity.setVerifier("verifier");
        userEntity.setSaltKey("saltKey");
        return userEntity;
    }

    private CredentialsEntity generateCredentialsEntity() {
        CredentialsEntity credentialsEntity = new CredentialsEntity();
        credentialsEntity.setCredentialsId(UUID.randomUUID());
        credentialsEntity.setWebsite(UUID.randomUUID().toString());
        credentialsEntity.setUsername(UUID.randomUUID().toString());
        credentialsEntity.setPassword(UUID.randomUUID().toString());
        credentialsEntity.setIvWebsite(UUID.randomUUID().toString());
        credentialsEntity.setIvUsername(UUID.randomUUID().toString());
        credentialsEntity.setIvPassword(UUID.randomUUID().toString());
        credentialsEntity.setLastUpdated(Instant.now());
        return credentialsEntity;
    }

}
