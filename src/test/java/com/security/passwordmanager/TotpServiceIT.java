package com.security.passwordmanager;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.passwordmanager.exceptions.MfaException;
import com.security.passwordmanager.helpers.EncryptionService;
import com.security.passwordmanager.helpers.TokenGenerator;
import com.security.passwordmanager.helpers.TokenHasher;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.mfa.TotpDao;
import com.security.passwordmanager.model.mfa.TotpEntity;
import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.TotpLoginEntity;
import com.security.passwordmanager.redis.entities.TotpNonceEntity;
import com.security.passwordmanager.redis.entities.TotpRedisEntity;
import com.security.passwordmanager.service.mfa.TotpService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.util.UriComponentsBuilder;
import xyz.segurapass.api.authorization.LoginCompleteResp;
import xyz.segurapass.api.credentials.NonceResp;
import xyz.segurapass.api.mfa.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.*;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

import static com.security.passwordmanager.shared.HelperMethods.generateUserEntity;
import static com.security.passwordmanager.exceptions.ErrorEnum.*;
import static org.junit.jupiter.api.Assertions.*;
import static com.security.passwordmanager.shared.HelperMethods.*;

@Slf4j
@SpringBootTest
public class TotpServiceIT extends AbstractTestInitializer {

    @Autowired
    private TotpService totpService;
    @Autowired
    private UserDao userDao;
    @Autowired
    private TotpDao totpDao;
    @Autowired
    private RedisService redisService;
    @Autowired
    private EncryptionService encryptionService;
    @Autowired
    private TokenGenerator tokenGenerator;
    @Autowired
    private TokenHasher tokenHasher;
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
        userEntity.setPublicSigningKey(
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
        );
        userDao.save(userEntity);
    }

    @AfterEach
    void cleanup() {
        totpDao.deleteAll();
        userDao.deleteAll();
        // auditLogDao.deleteAll();
        redisService.clearAll();
        MDC.clear();
    }

    @Test
    void shouldFailTotpAlreadyExistsAddTotpStart() {
        // given
        UserEntity userEntity = userDao.findByUserId(userId);
        TotpEntity totpEntity = generateTotpEntity(userEntity);
        totpDao.save(totpEntity);

        // when
        MfaException ex = assertThrows(
                MfaException.class,
                () -> totpService.addTotpStart(userId, deviceId)
        );

        // then
        assertEquals(MFA_TOTP_ALREADY_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(MFA_TOTP_ALREADY_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedAddTotpStart() {
        // when
        ResponseEntity<NonceResp> response = totpService.addTotpStart(userId, deviceId);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        String nonce = response.getBody().getNonce();
        assertNotNull(nonce);
        String redisKey = RedisKeys.mfaNonce(nonce);
        TotpNonceEntity nonceEntity = redisService.get(redisKey, TotpNonceEntity.class);
        assertEquals(userId, nonceEntity.getUserId());
        assertEquals(deviceId, nonceEntity.getDeviceId());
        assertEquals(MfaType.TOTP_ADD, nonceEntity.getMfaType());
    }

    @Test
    void shouldFailNonceMissingAddTotpEnd() {
        // given
        TotpReq req = new TotpReq();
        req.setNonce(null);

        // when
        MfaException ex = assertThrows(
                MfaException.class,
                () -> totpService.addTotpEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(MFA_NONCE_MISSING.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(MFA_NONCE_MISSING.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailNonceNotFoundAddTotpEnd() {
        // given
        TotpReq req = new TotpReq();
        req.setNonce(UUID.randomUUID().toString());

        // when
        MfaException ex = assertThrows(
                MfaException.class,
                () -> totpService.addTotpEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(NONCE_NOT_FOUND.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(NONCE_NOT_FOUND.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailNonceEntityNullAddTotpEnd() {
        // given
        String nonce = UUID.randomUUID().toString();
        TotpReq req = new TotpReq();
        req.setNonce(nonce);
        String redisKey = RedisKeys.mfaNonce(nonce);
        redisService.save(redisKey, null, Duration.of(60, ChronoUnit.SECONDS));

        // when
        MfaException ex = assertThrows(
                MfaException.class,
                () -> totpService.addTotpEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(NONCE_ERROR.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(NONCE_ERROR.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailNonceUserIdMismatchAddTotpEnd() {
        // given
        String nonce = UUID.randomUUID().toString();
        TotpReq req = new TotpReq();
        req.setNonce(nonce);
        String redisKey = RedisKeys.mfaNonce(nonce);
        TotpNonceEntity nonceEntity = generateTotpNonceEntity(MfaType.TOTP_ADD);
        redisService.save(redisKey, nonceEntity, Duration.of(60, ChronoUnit.SECONDS));

        // when
        MfaException ex = assertThrows(
                MfaException.class,
                () -> totpService.addTotpEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(NONCE_ERROR.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(NONCE_ERROR.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailNonceDeviceIdMismatchAddTotpEnd() {
        // given
        String nonce = UUID.randomUUID().toString();
        TotpReq req = new TotpReq();
        req.setNonce(nonce);
        String redisKey = RedisKeys.mfaNonce(nonce);
        TotpNonceEntity nonceEntity = generateTotpNonceEntity(MfaType.TOTP_ADD);
        nonceEntity.setUserId(userId);
        redisService.save(redisKey, nonceEntity, Duration.of(60, ChronoUnit.SECONDS));

        // when
        MfaException ex = assertThrows(
                MfaException.class,
                () -> totpService.addTotpEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(NONCE_ERROR.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(NONCE_ERROR.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailMfaTypeMismatchAddTotpEnd() {
        // given
        String nonce = UUID.randomUUID().toString();
        TotpReq req = new TotpReq();
        req.setNonce(nonce);
        req.setMfaType(MfaType.TOTP_REMOVE);
        String redisKey = RedisKeys.mfaNonce(nonce);
        TotpNonceEntity nonceEntity = generateTotpNonceEntity(MfaType.TOTP_ADD);
        nonceEntity.setUserId(userId);
        nonceEntity.setDeviceId(deviceId);
        redisService.save(redisKey, nonceEntity, Duration.of(60, ChronoUnit.SECONDS));

        // when
        MfaException ex = assertThrows(
                MfaException.class,
                () -> totpService.addTotpEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(NONCE_ERROR.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(NONCE_ERROR.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailInvalidSignatureAddTotpEnd() {
        // given
        String nonce = UUID.randomUUID().toString();
        TotpReq req = new TotpReq();
        req.setNonce(nonce);
        req.setMfaType(MfaType.TOTP_ADD);
        String redisKey = RedisKeys.mfaNonce(nonce);
        TotpNonceEntity nonceEntity = generateTotpNonceEntity(MfaType.TOTP_ADD);
        nonceEntity.setUserId(userId);
        nonceEntity.setDeviceId(deviceId);
        redisService.save(redisKey, nonceEntity, Duration.of(60, ChronoUnit.SECONDS));

        // when
        MfaException ex = assertThrows(
                MfaException.class,
                () -> totpService.addTotpEnd(req, userId, deviceId, null)
        );

        // then
        assertEquals(INVALID_SIGNATURE.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(INVALID_SIGNATURE.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedAddTotpEnd() throws Exception {
        // given
        String nonce = Objects.requireNonNull(
                totpService.addTotpStart(userId, deviceId).getBody()
        ).getNonce();
        TotpReq req = new TotpReq();
        req.setNonce(nonce);
        req.setMfaType(MfaType.TOTP_ADD);
        String signature = createSignature(req, privateKey);
        assertTrue(redisService.exists(RedisKeys.mfaNonce(nonce)));
        assertNull(totpDao.findByUserEntity_UserId(userId));
        assertFalse(redisService.exists(RedisKeys.totpVerification(userId.toString(), deviceId.toString())));

        // when
        ResponseEntity<TotpResp> response = totpService.addTotpEnd(req, userId, deviceId, signature);

        // then
        assertFalse(redisService.exists(RedisKeys.mfaNonce(nonce)));
        assertTrue(redisService.exists(RedisKeys.totpVerification(userId.toString(), deviceId.toString())));
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        String totpUrl = response.getBody().getTotpUrl();
        assertNotNull(totpUrl);
    }

    @Test
    void shouldFailTotpEntityNotExistsRemoveTotpStart() {
        // when
        MfaException ex = assertThrows(
                MfaException.class,
                () -> totpService.removeTotpStart(userId, deviceId)
        );

        // then
        assertEquals(MFA_TOTP_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(MFA_TOTP_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedRemoveTotpStart() {
        // given
        UserEntity userEntity = userDao.findByUserId(userId);
        TotpEntity totpEntity = generateTotpEntity(userEntity);
        totpDao.save(totpEntity);

        // when
        ResponseEntity<NonceResp> response = totpService.removeTotpStart(userId, deviceId);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        String nonce = response.getBody().getNonce();
        assertNotNull(nonce);
        String redisKey = RedisKeys.mfaNonce(nonce);
        TotpNonceEntity nonceEntity = redisService.get(redisKey, TotpNonceEntity.class);
        assertEquals(userId, nonceEntity.getUserId());
        assertEquals(deviceId, nonceEntity.getDeviceId());
        assertEquals(MfaType.TOTP_REMOVE, nonceEntity.getMfaType());
    }

    @Test
    void shouldSucceedRemoveTotpEnd() throws Exception {
        // given
        UserEntity userEntity = userDao.findByUserId(userId);
        userEntity.setMfaEnabled(true);
        userEntity.setMfaRecoveryCode(UUID.randomUUID().toString());
        userDao.save(userEntity);
        TotpEntity totpEntity = generateTotpEntity(userEntity);
        totpDao.save(totpEntity);
        String nonce = Objects.requireNonNull(
                totpService.removeTotpStart(userId, deviceId).getBody()
        ).getNonce();
        TotpReq req = new TotpReq();
        req.setNonce(nonce);
        req.setMfaType(MfaType.TOTP_REMOVE);
        String signature = createSignature(req, privateKey);
        assertTrue(redisService.exists(RedisKeys.mfaNonce(nonce)));
        assertNotNull(totpDao.findByUserEntity_UserId(userId));
        assertTrue(userDao.findByUserId(userId).getMfaEnabled());
        assertNotNull(userDao.findByUserId(userId).getMfaRecoveryCode());

        // when
        ResponseEntity<Void> response = totpService.removeTotpEnd(req, userId, deviceId, signature);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertFalse(redisService.exists(RedisKeys.mfaNonce(nonce)));
        assertNull(totpDao.findByUserEntity_UserId(userId));
        assertFalse(userDao.findByUserId(userId).getMfaEnabled());
        assertNull(userDao.findByUserId(userId).getMfaRecoveryCode());
    }

    @Test
    void shouldSucceedVerifyTotp() throws Exception {
        // given
        String nonce = Objects.requireNonNull(
                totpService.addTotpStart(userId, deviceId).getBody()
        ).getNonce();

        TotpReq req = new TotpReq();
        req.setNonce(nonce);
        req.setMfaType(MfaType.TOTP_ADD);

        String signature = createSignature(req, privateKey);

        String totpUrl = Objects.requireNonNull(
                totpService.addTotpEnd(req, userId, deviceId, signature).getBody()
        ).getTotpUrl();
        System.out.println("TOTP URL:  " + totpUrl);

        String redisKey = RedisKeys.totpVerification(userId.toString(), deviceId.toString());
        assertTrue(redisService.exists(redisKey));
        TotpRedisEntity encryptedSecret = redisService.get(redisKey, TotpRedisEntity.class);
        byte[] totpSecretBytes = encryptionService.decryptTotpSecret(
                encryptedSecret.getEncryptedTotpSecret(),
                encryptedSecret.getIv()
        );
        assertEquals(
                new Base32().encodeToString(totpSecretBytes),
                UriComponentsBuilder.fromUri(URI.create(totpUrl))
                        .build()
                        .getQueryParams()
                        .getFirst("secret")
        );
        assertNull(totpDao.findByUserEntity_UserId(userId));
        assertFalse(userDao.findByUserId(userId).getMfaEnabled());

        // when
        String otp = generateOtp(totpSecretBytes);
        TotpVerifyReq verifyReq = new TotpVerifyReq(otp);
        ResponseEntity<TotpVerifyResp> response = totpService.verifyTotp(verifyReq, userId, deviceId);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().getRecoveryCode());
        assertFalse(redisService.exists(redisKey));
        TotpEntity totpEntity = totpDao.findByUserEntity_UserId(userId);
        assertNotNull(totpEntity);
        assertEquals(encryptedSecret.getEncryptedTotpSecret(), totpEntity.getEncryptedToken());
        assertEquals(encryptedSecret.getIv(), totpEntity.getTokenIv());
        UserEntity userEntity = userDao.findByUserId(userId);
        assertTrue(userEntity.getMfaEnabled());
        assertEquals(
                tokenHasher.generateSha256(response.getBody().getRecoveryCode()),
                userEntity.getMfaRecoveryCode()
        );
    }

    @Test
    void shouldFailRedisKeyNotExistsLoginTotp() {
        // when
        MfaException ex = assertThrows(
                MfaException.class,
                () -> totpService.totpLogin(UUID.randomUUID().toString(), null)
        );

        // then
        assertEquals(MFA_TOTP_LOGIN_MISSING_KEY.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(MFA_TOTP_LOGIN_MISSING_KEY.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailDecryptionFailureLoginTotp() {
        // given
        TotpLoginEntity totpLoginEntity = new TotpLoginEntity(
                userId,
                deviceId,
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString()
        );
        String totpCode = tokenGenerator.generateRandomToken(32);
        String redisKey = RedisKeys.totpLogin(tokenHasher.generateSha256(totpCode));
        redisService.save(redisKey, totpLoginEntity, Duration.of(10, ChronoUnit.MINUTES));

        // when
        MfaException ex = assertThrows(
                MfaException.class,
                () -> totpService.totpLogin(totpCode, null)
        );

        // then
        assertEquals(MFA_TOTP_DECRYPTION_FAILED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(MFA_TOTP_DECRYPTION_FAILED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailOtpVerificationFailureLoginTotp() throws Exception {
        // given
        String totpSecret = tokenGenerator.generateTotpSecret();
        TotpRedisEntity totpRedisEntity = encryptionService.encryptTotpSecret(totpSecret);
        TotpLoginEntity totpLoginEntity = new TotpLoginEntity(
                userId,
                deviceId,
                totpRedisEntity.getEncryptedTotpSecret(),
                totpRedisEntity.getIv()
        );
        String totpCode = tokenGenerator.generateRandomToken(32);
        String redisKey = RedisKeys.totpLogin(tokenHasher.generateSha256(totpCode));
        redisService.save(redisKey, totpLoginEntity, Duration.of(10, ChronoUnit.MINUTES));
        TotpVerifyReq req = new TotpVerifyReq("0123456789");

        // when
        MfaException ex = assertThrows(
                MfaException.class,
                () -> totpService.totpLogin(totpCode, req)
        );

        // then
        assertEquals(MFA_TOTP_VERIFICATION_FAILED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(MFA_TOTP_VERIFICATION_FAILED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedLoginTotp() throws Exception {
        // given
        String totpSecret = tokenGenerator.generateTotpSecret();
        TotpRedisEntity totpRedisEntity = encryptionService.encryptTotpSecret(totpSecret);
        TotpLoginEntity totpLoginEntity = new TotpLoginEntity(
                userId,
                deviceId,
                totpRedisEntity.getEncryptedTotpSecret(),
                totpRedisEntity.getIv()
        );
        String totpCode = tokenGenerator.generateRandomToken(32);
        String redisKey = RedisKeys.totpLogin(tokenHasher.generateSha256(totpCode));
        redisService.save(redisKey, totpLoginEntity, Duration.of(10, ChronoUnit.MINUTES));
        byte[] totpSecretDecrypted = encryptionService.decryptTotpSecret(
                totpRedisEntity.getEncryptedTotpSecret(),
                totpRedisEntity.getIv()
        );
        TotpVerifyReq req = new TotpVerifyReq(generateOtp(totpSecretDecrypted));

        // when
        ResponseEntity<LoginCompleteResp> response = totpService.totpLogin(totpCode, req);

        // then
        UserEntity userEntity = userDao.findByUserId(userId);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        LoginCompleteResp body = response.getBody();
        assertNotNull(body);
        assertFalse(redisService.exists(redisKey));
        assertEquals(userEntity.getVaultKey(), body.getVaultKey());
        assertNotNull(body.getAccessToken());
        assertNotNull(body.getRefreshToken());
        assertNull(body.getTotpCode());
    }

    private String createSignature(
            TotpReq req,
            PrivateKey privateKey
    ) throws Exception
    {
        TotpPayload payload = new TotpPayload(
                req.getMfaType(),
                req.getNonce()
        );

        byte[] payloadBytes = objectMapper.writeValueAsBytes(payload);

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privateKey);
        signer.update(payloadBytes);

        byte[] signatureBytes = signer.sign();

        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private String generateOtp(byte[] secret) throws Exception {
        System.out.println("TEST SECRET: " +
                HexFormat.of().formatHex(secret));

        long currentTimeStep = System.currentTimeMillis() / 1000 / totpService.getTOTP_PERIOD();

        int binaryCode = 0;

        for(long i = 0; i <= 3; i++) {
            long timeStep = currentTimeStep + i;
            System.out.println("TIMESTEPS:   " + timeStep);

            byte[] counter = ByteBuffer.allocate(Long.BYTES)
                    .putLong(timeStep)
                    .array();

            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));

            byte[] hash = mac.doFinal(counter);

            int offsetValue = hash[hash.length - 1] & 0x0F;

            int binaryCodeInternal =
                    ((hash[offsetValue] & 0x7F) << 24)
                            | ((hash[offsetValue + 1] & 0xFF) << 16)
                            | ((hash[offsetValue + 2] & 0xFF) << 8)
                            | (hash[offsetValue + 3] & 0xFF);

            System.out.println("INTERNAL BINARY CODE:   " + String.format("%06d", binaryCodeInternal % 1_000_000));

            if (i == 0) {
                binaryCode = binaryCodeInternal;
            }
        }

        return String.format("%06d", binaryCode % 1_000_000);
    }

}
