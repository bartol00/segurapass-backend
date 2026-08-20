package com.security.passwordmanager;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.passwordmanager.model.audit.AuditLogDao;
import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.CredentialsWriteEntity;
import org.junit.jupiter.api.*;
import xyz.segurapass.api.credentials.*;
import com.security.passwordmanager.exceptions.CredentialsException;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.credentials.CredentialsDao;
import com.security.passwordmanager.model.credentials.CredentialsEntity;
import com.security.passwordmanager.service.CredentialsService;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.*;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static com.security.passwordmanager.exceptions.enums.ErrorEnum.*;
import static org.junit.jupiter.api.Assertions.*;
import static com.security.passwordmanager.shared.HelperMethods.*;

@SpringBootTest
public class CredentialsServiceIT extends AbstractTestInitializer {

    @Autowired
    private CredentialsService credentialsService;
    @Autowired
    private UserDao userDao;
    @Autowired
    private CredentialsDao credentialsDao;
    @Autowired
    private AuditLogDao auditLogDao;
    @Autowired
    private RedisService redisService;
    @Autowired
    private ObjectMapper objectMapper;

    private PrivateKey privateKey;

    @BeforeEach
    void setup() throws NoSuchAlgorithmException {
        MDC.put("clientIp", "127.0.0.1");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = generator.generateKeyPair();
        privateKey = keyPair.getPrivate();

        UserEntity userEntity = generateUserEntity();
        userEntity.setPublicSigningKeyBytes(
                keyPair.getPublic().getEncoded()
        );
        userDao.save(userEntity);

        CredentialsEntity credentialsEntity1 = generateCredentialsEntity(userEntity);
        CredentialsEntity credentialsEntity2 = generateCredentialsEntity(userEntity);
        CredentialsEntity credentialsEntity3 = generateCredentialsEntity(userEntity);
        List<CredentialsEntity> credentialsEntityList = List.of(credentialsEntity1, credentialsEntity2, credentialsEntity3);
        credentialsDao.saveAll(credentialsEntityList);
    }

    @AfterEach
    void clean() {
        privateKey = null;
        redisService.clearAll();
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
        assertArrayEquals(resp.getWebsiteBytes(), credentialsEntity.getWebsiteBytes());
        assertArrayEquals(resp.getIvWebsiteBytes(), credentialsEntity.getIvWebsiteBytes());
    }

    @Test
    void shouldSucceedCreateCredentialsStart() {
        // when
        ResponseEntity<NonceResp> response = credentialsService.createCredentialsStart(userId, deviceId);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        String nonce = response.getBody().getNonce();
        assertNotNull(nonce);
        String redisKey = RedisKeys.credentialsNonce(nonce);
        CredentialsWriteEntity writeEntity = redisService.get(redisKey, CredentialsWriteEntity.class);
        assertEquals(userId, writeEntity.getUserId());
        assertEquals(deviceId, writeEntity.getDeviceId());
        assertEquals(CredentialsOperation.CREATE, writeEntity.getOperation());
        assertNull(writeEntity.getCredentialsId());
    }

    @Test
    void shouldFailCredentialNonceMissingCreateCredentialsEnd() {
        // given
        CredentialsReq req = new CredentialsReq();
        req.setNonce(null);

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.createCredentialsEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(CREDENTIAL_NONCE_MISSING.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(CREDENTIAL_NONCE_MISSING.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailNonceNotFoundCreateCredentialsEnd() {
        // given
        CredentialsReq req = new CredentialsReq();
        req.setNonce(UUID.randomUUID().toString());

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.createCredentialsEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(NONCE_NOT_FOUND.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(NONCE_NOT_FOUND.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailWriteEntityNullNonceErrorCreateCredentialsEnd() {
        // given
        CredentialsReq req = new CredentialsReq();
        req.setNonce("nonce");
        redisService.save(RedisKeys.credentialsNonce("nonce"), null, Duration.of(60, ChronoUnit.SECONDS));

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.createCredentialsEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(NONCE_ERROR.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(NONCE_ERROR.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailWriteEntityUserIdMismatchNonceErrorCreateCredentialsEnd() {
        // given
        CredentialsReq req = new CredentialsReq();
        req.setNonce("nonce");
        CredentialsWriteEntity writeEntity = createWriteEntity(
                UUID.randomUUID(),
                UUID.randomUUID(),
                CredentialsOperation.CREATE,
                UUID.randomUUID()
        );
        redisService.save(RedisKeys.credentialsNonce("nonce"), writeEntity, Duration.of(60, ChronoUnit.SECONDS));

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.createCredentialsEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(NONCE_ERROR.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(NONCE_ERROR.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailWriteEntityDeviceIdMismatchNonceErrorCreateCredentialsEnd() {
        // given
        CredentialsReq req = new CredentialsReq();
        req.setNonce("nonce");
        CredentialsWriteEntity writeEntity = createWriteEntity(
                userId,
                UUID.randomUUID(),
                CredentialsOperation.CREATE,
                UUID.randomUUID()
        );
        redisService.save(RedisKeys.credentialsNonce("nonce"), writeEntity, Duration.of(60, ChronoUnit.SECONDS));

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.createCredentialsEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(NONCE_ERROR.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(NONCE_ERROR.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailWriteEntityOperationMismatchNonceErrorCreateCredentialsEnd() {
        // given
        CredentialsReq req = new CredentialsReq();
        req.setNonce("nonce");
        CredentialsWriteEntity writeEntity = createWriteEntity(
                userId,
                deviceId,
                CredentialsOperation.DELETE,
                UUID.randomUUID()
        );
        redisService.save(RedisKeys.credentialsNonce("nonce"), writeEntity, Duration.of(60, ChronoUnit.SECONDS));

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.createCredentialsEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(NONCE_ERROR.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(NONCE_ERROR.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailWriteEntityCredentialsIdMismatchNonceErrorCreateCredentialsEnd() {
        // given
        CredentialsReq req = new CredentialsReq();
        req.setNonce("nonce");
        CredentialsWriteEntity writeEntity = createWriteEntity(
                userId,
                deviceId,
                CredentialsOperation.CREATE,
                UUID.randomUUID()
        );
        redisService.save(RedisKeys.credentialsNonce("nonce"), writeEntity, Duration.of(60, ChronoUnit.SECONDS));

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.createCredentialsEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(NONCE_ERROR.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(NONCE_ERROR.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailInvalidSignatureCreateCredentialsEnd() throws Exception {
        // given
        String nonce = Objects.requireNonNull(
                credentialsService.createCredentialsStart(userId, deviceId).getBody()
        ).getNonce();
        CredentialsReq req = generateCredentialsReq();
        req.setNonce(nonce);
        req.setOperation(CredentialsOperation.CREATE);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = generator.generateKeyPair();
        String signature = createSignature(req, null, keyPair.getPrivate());

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.createCredentialsEnd(req, userId, deviceId, signature)
        );

        // then
        assertEquals(INVALID_SIGNATURE.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(INVALID_SIGNATURE.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedCreateCredentialsEnd() throws Exception {
        // given
        String nonce = Objects.requireNonNull(
                credentialsService.createCredentialsStart(userId, deviceId).getBody()
        ).getNonce();
        CredentialsReq req = generateCredentialsReq();
        req.setNonce(nonce);
        req.setOperation(CredentialsOperation.CREATE);
        String signature = createSignature(req, null, privateKey);
        long count = credentialsDao.count();

        // when
        ResponseEntity<CredentialsResp> response = credentialsService.createCredentialsEnd(
                req, userId, deviceId, signature
        );
        CredentialsResp resp = response.getBody();

        // then
        assertEquals(count + 1, credentialsDao.count());
        assertEquals(1, auditLogDao.findAll().size());
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(resp);
        assertArrayEquals(resp.getWebsiteBytes(), req.getWebsiteBytes());
        assertArrayEquals(resp.getIvWebsiteBytes(), req.getIvWebsiteBytes());
    }

    @Test
    void shouldSucceedUpdateCredentialsStart() {
        // given
        List<CredentialsEntity> credentialsEntityList = credentialsDao.findAll();
        CredentialsEntity credentialsEntity = credentialsEntityList.getFirst();
        UUID credentialsId = credentialsEntity.getCredentialsId();

        // when
        ResponseEntity<NonceResp> response = credentialsService.updateCredentialsStart(
                credentialsId,
                userId,
                deviceId
        );

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        String nonce = response.getBody().getNonce();
        assertNotNull(nonce);
        String redisKey = RedisKeys.credentialsNonce(nonce);
        CredentialsWriteEntity writeEntity = redisService.get(redisKey, CredentialsWriteEntity.class);
        assertEquals(userId, writeEntity.getUserId());
        assertEquals(deviceId, writeEntity.getDeviceId());
        assertEquals(CredentialsOperation.UPDATE, writeEntity.getOperation());
        assertEquals(credentialsId, writeEntity.getCredentialsId());
    }

    @Test
    void shouldFailCredentialIsNullUpdateCredentialsEnd() throws Exception {
        // given
        UUID credentialsId = UUID.randomUUID();
        String nonce = Objects.requireNonNull(
                credentialsService.updateCredentialsStart(credentialsId, userId, deviceId).getBody()
        ).getNonce();
        CredentialsReq req = generateCredentialsReq();
        req.setNonce(nonce);
        req.setOperation(CredentialsOperation.UPDATE);
        String signature = createSignature(req, credentialsId, privateKey);

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.updateCredentialsEnd(credentialsId, req, userId, deviceId, signature)
        );

        // then
        assertEquals(CREDENTIAL_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(CREDENTIAL_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailMissingIvUpdateCredentialsEnd() throws Exception {
        // given
        List<CredentialsEntity> credentialsEntityList = credentialsDao.findAll();
        CredentialsEntity credentialsEntity = credentialsEntityList.getFirst();
        UUID credentialsId = credentialsEntity.getCredentialsId();
        String nonce = Objects.requireNonNull(
                credentialsService.updateCredentialsStart(credentialsId, userId, deviceId).getBody()
        ).getNonce();
        CredentialsReq req = generateCredentialsReq();
        req.setIvWebsiteBytes(null);
        req.setNonce(nonce);
        req.setOperation(CredentialsOperation.UPDATE);
        String signature = createSignature(req, credentialsId, privateKey);

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.updateCredentialsEnd(credentialsId, req, userId, deviceId, signature)
        );

        // then
        assertEquals(CREDENTIAL_UPDATE_IV_MISSING.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(CREDENTIAL_UPDATE_IV_MISSING.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedUpdateCredentialsEnd() throws Exception {
        // given
        List<CredentialsEntity> credentialsEntityList = credentialsDao.findAll();
        CredentialsEntity credentialsEntity = credentialsEntityList.getFirst();
        UUID credentialsId = credentialsEntity.getCredentialsId();
        String nonce = Objects.requireNonNull(
                credentialsService.updateCredentialsStart(credentialsId, userId, deviceId).getBody()
        ).getNonce();
        CredentialsReq req = generateCredentialsReq();
        req.setNonce(nonce);
        req.setOperation(CredentialsOperation.UPDATE);
        String signature = createSignature(req, credentialsId, privateKey);

        // when
        ResponseEntity<CredentialsResp> response = credentialsService.updateCredentialsEnd(
                credentialsId, req, userId, deviceId, signature
        );
        CredentialsResp resp = response.getBody();

        // then
        assertEquals(1, auditLogDao.findAll().size());
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(resp);
        assertFalse(Arrays.equals(credentialsEntity.getIvWebsiteBytes(), resp.getIvWebsiteBytes()));
        assertFalse(Arrays.equals(credentialsEntity.getIvUsernameBytes(), resp.getIvUsernameBytes()));
        assertFalse(Arrays.equals(credentialsEntity.getIvPasswordBytes(), resp.getIvUsernameBytes()));
    }

    @Test
    void shouldSucceedDeleteCredentialsStart() {
        // given
        List<CredentialsEntity> credentialsEntityList = credentialsDao.findAll();
        CredentialsEntity credentialsEntity = credentialsEntityList.getFirst();
        UUID credentialsId = credentialsEntity.getCredentialsId();

        // when
        ResponseEntity<NonceResp> response = credentialsService.deleteCredentialsStart(
                credentialsId,
                userId,
                deviceId
        );

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        String nonce = response.getBody().getNonce();
        assertNotNull(nonce);
        String redisKey = RedisKeys.credentialsNonce(nonce);
        CredentialsWriteEntity writeEntity = redisService.get(redisKey, CredentialsWriteEntity.class);
        assertEquals(userId, writeEntity.getUserId());
        assertEquals(deviceId, writeEntity.getDeviceId());
        assertEquals(CredentialsOperation.DELETE, writeEntity.getOperation());
        assertEquals(credentialsId, writeEntity.getCredentialsId());
    }

    @Test
    void shouldFailCredentialIsNullDeleteCredentialsEnd() throws Exception {
        // given
        UUID credentialsId = UUID.randomUUID();
        String nonce = Objects.requireNonNull(
                credentialsService.deleteCredentialsStart(credentialsId, userId, deviceId).getBody()
        ).getNonce();
        CredentialsReq req = new CredentialsReq();
        req.setNonce(nonce);
        req.setOperation(CredentialsOperation.DELETE);
        String signature = createSignature(req, credentialsId, privateKey);

        // when
        CredentialsException ex = assertThrows(
                CredentialsException.class,
                () -> credentialsService.deleteCredentialsEnd(credentialsId, req, userId, deviceId, signature)
        );

        // then
        assertEquals(CREDENTIAL_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(CREDENTIAL_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedDeleteCredentialsEnd() throws Exception {
        // given
        List<CredentialsEntity> credentialsEntityList = credentialsDao.findAll();
        CredentialsEntity credentialsEntity = credentialsEntityList.getFirst();
        UUID credentialsId = credentialsEntity.getCredentialsId();
        String nonce = Objects.requireNonNull(
                credentialsService.deleteCredentialsStart(credentialsId, userId, deviceId).getBody()
        ).getNonce();
        CredentialsReq req = new CredentialsReq();
        req.setNonce(nonce);
        req.setOperation(CredentialsOperation.DELETE);
        String signature = createSignature(req, credentialsId, privateKey);
        long count = credentialsDao.count();

        // when
        ResponseEntity<Void> response = credentialsService.deleteCredentialsEnd(
                credentialsId, req, userId, deviceId, signature
        );

        // then
        assertEquals(1, auditLogDao.findAll().size());
        assertEquals(count - 1, credentialsDao.count());
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(credentialsDao.findById(credentialsEntity.getId()).isEmpty());
    }

    private String createSignature(CredentialsReq req, UUID credentialsId, PrivateKey privateKey) throws Exception {
        CredentialsWritePayload payload =
                new CredentialsWritePayload(
                        req.getWebsiteBytes(),
                        req.getUsernameBytes(),
                        req.getPasswordBytes(),
                        req.getIvWebsiteBytes(),
                        req.getIvUsernameBytes(),
                        req.getIvPasswordBytes(),
                        req.getNonce(),
                        req.getOperation(),
                        credentialsId
                );

        byte[] payloadBytes = objectMapper.writeValueAsBytes(payload);

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privateKey);
        signer.update(payloadBytes);

        byte[] signatureBytes = signer.sign();

        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private CredentialsWriteEntity createWriteEntity(
            UUID userId, UUID deviceId, CredentialsOperation operation, UUID credentialsId
    ) {
        return new CredentialsWriteEntity(
                userId, deviceId, operation, credentialsId
        );
    }

}
