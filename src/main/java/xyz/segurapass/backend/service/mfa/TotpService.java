package xyz.segurapass.backend.service.mfa;

import com.fasterxml.jackson.databind.ObjectMapper;
import xyz.segurapass.backend.exceptions.MfaException;
import xyz.segurapass.backend.helpers.*;
import xyz.segurapass.backend.model.authorization.UserDao;
import xyz.segurapass.backend.model.authorization.UserEntity;
import xyz.segurapass.backend.model.mfa.TotpDao;
import xyz.segurapass.backend.model.mfa.TotpEntity;
import xyz.segurapass.backend.redis.RedisKeys;
import xyz.segurapass.backend.redis.RedisService;
import jakarta.transaction.Transactional;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import xyz.segurapass.api.authorization.LoginCompleteResp;
import xyz.segurapass.api.credentials.NonceResp;
import xyz.segurapass.api.mfa.*;
import xyz.segurapass.backend.redis.entities.TotpLoginEntity;
import xyz.segurapass.backend.redis.entities.TotpNonceEntity;
import xyz.segurapass.backend.redis.entities.TotpRedisEntity;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static xyz.segurapass.backend.exceptions.enums.ErrorEnum.*;
import static xyz.segurapass.backend.exceptions.enums.ErrorEnum.INVALID_SIGNATURE;
import static xyz.segurapass.backend.exceptions.enums.ErrorEnum.NONCE_ERROR;

@Service
@RequiredArgsConstructor
@Slf4j
public class TotpService {

    private final TokenGenerator tokenGenerator;
    private final TokenHasher tokenHasher;
    private final RedisService redisService;
    private final EncryptionService encryptionService;
    private final SignatureService signatureService;
    private final LoginHelper loginHelper;
    private final NonceHelper nonceHelper;

    private final UserDao userDao;
    private final TotpDao totpDao;

    private final ObjectMapper objectMapper;

    @Getter
    private final String TOTP_ALGORITHM = "SHA1";
    @Getter
    private final int TOTP_DIGITS = 6;
    @Getter
    private final int TOTP_PERIOD = 30;


    public ResponseEntity<NonceResp> addTotpStart(UUID userId, UUID deviceId) {
        if (totpDao.findByUserEntity_UserId(userId) != null) {
            log.warn("TOTP already exists for this user - Add TOTP Start");
            throw new MfaException(MFA_TOTP_ALREADY_EXISTS);
        }
        String nonce = generateNonce(userId, deviceId, MfaType.TOTP_ADD);
        log.info("Start TOTP Add");
        return ResponseEntity.ok(new NonceResp(nonce));
    }

    public ResponseEntity<TotpResp> addTotpEnd(
            TotpReq req,
            UUID userId,
            UUID deviceId,
            String signature
    ) {
        verifyNonceAndSignature(userId, deviceId, req, signature);

        UserEntity userEntity = userDao.findByUserId(userId);

        String totpSecret = tokenGenerator.generateTotpSecret();
        String totpUri = createTotpUri(userEntity.getEmail(), totpSecret);

        TotpRedisEntity totpRedisEntity;
        try {
            totpRedisEntity = encryptionService.encryptTotpSecret(totpSecret);
        } catch (Exception e) {
            log.warn("Exception occurred during TOTP secret encryption", e);
            throw new MfaException(MFA_TOTP_ENCRYPTION_FAILED);
        }

        String redisKey = RedisKeys.totpVerification(userId.toString(), deviceId.toString());
        redisService.save(redisKey, totpRedisEntity, Duration.of(10, ChronoUnit.MINUTES));

        log.info("Complete TOTP Add");

        return ResponseEntity.ok(new TotpResp(totpUri));
    }

    public ResponseEntity<NonceResp> removeTotpStart(UUID userId, UUID deviceId) {
        if (totpDao.findByUserEntity_UserId(userId) == null) {
            log.warn("TOTP for this user does not exist");
            throw new MfaException(MFA_TOTP_NOT_EXISTS);
        }
        String nonce = generateNonce(userId, deviceId, MfaType.TOTP_REMOVE);
        log.info("Start TOTP Remove");
        return ResponseEntity.ok(new NonceResp(nonce));
    }

    @Transactional
    public ResponseEntity<Void> removeTotpEnd(
            TotpReq req,
            UUID userId,
            UUID deviceId,
            String signature
    ) {
        verifyNonceAndSignature(userId, deviceId, req, signature);
        totpDao.deleteByUserEntity_UserId(userId);
        UserEntity userEntity = userDao.findByUserId(userId);
        userEntity.setTotpEnabled(false);
        userEntity.setMfaRecoveryCode(null);
        userEntity.setTotpEntity(null);
        userDao.save(userEntity);
        log.info("Complete TOTP Remove");
        return ResponseEntity.ok(null);
    }

    @Transactional
    public ResponseEntity<TotpVerifyResp> verifyTotp(
            TotpVerifyReq req,
            UUID userId,
            UUID deviceId
    ) {
        if (totpDao.findByUserEntity_UserId(userId) != null) {
            log.warn("TOTP already exists for this user - Verify TOTP");
            throw new MfaException(MFA_TOTP_ALREADY_EXISTS);
        }

        String redisKey = RedisKeys.totpVerification(userId.toString(), deviceId.toString());
        TotpRedisEntity totpRedisEntity = redisService.get(redisKey, TotpRedisEntity.class);

        byte[] totpSecretBytes;
        try {
            totpSecretBytes = encryptionService.decryptTotpSecret(
                    totpRedisEntity.getTotpSecretBytes(),
                    totpRedisEntity.getTotpSecretIv()
            );
        } catch (Exception e) {
            log.warn("Exception occurred during TOTP secret decryption - TOTP Verification", e);
            throw new MfaException(MFA_TOTP_DECRYPTION_FAILED);
        }

        if (!verifyTotp(totpSecretBytes, req.getOtp())) {
            log.warn("TOTP verification failed - TOTP Verify");
            throw new MfaException(MFA_TOTP_VERIFICATION_FAILED);
        }

        UserEntity userEntity = userDao.findByUserId(userId);

        TotpEntity totpEntity = new TotpEntity();
        totpEntity.setTotpTokenBytes(totpRedisEntity.getTotpSecretBytes());
        totpEntity.setTotpTokenIv(totpRedisEntity.getTotpSecretIv());
        totpEntity.setCreatedAt(Instant.now());
        totpEntity.setUserEntity(userEntity);
        totpDao.save(totpEntity);

        String mfaRecoveryCode = tokenGenerator.generateRandomToken(32);
        String recoveryHash = tokenHasher.generateSha256(mfaRecoveryCode);

        userEntity.setTotpEnabled(true);
        userEntity.setMfaRecoveryCode(recoveryHash);
        userEntity.setTotpEntity(totpEntity);
        userDao.save(userEntity);

        redisService.delete(redisKey);

        log.info("TOTP Verified");

        return ResponseEntity.ok(new TotpVerifyResp(mfaRecoveryCode));
    }

    @Transactional
    public ResponseEntity<LoginCompleteResp> totpLogin(
            String totpCode,
            TotpVerifyReq req
    ) {
        String redisKey = RedisKeys.totpLogin(tokenHasher.generateSha256(totpCode));
        if (!redisService.exists(redisKey)) {
            log.warn("Token does not exist {} - TOTP Login", redisKey);
            throw new MfaException(MFA_TOTP_LOGIN_MISSING_KEY);
        }

        TotpLoginEntity totpLoginEntity = redisService.get(redisKey, TotpLoginEntity.class);

        byte[] totpSecretBytes;
        try {
            totpSecretBytes = encryptionService.decryptTotpSecret(
                    totpLoginEntity.getTotpSecretBytes(),
                    totpLoginEntity.getTotpSecretIv()
            );
        } catch (Exception e) {
            log.warn("Exception occurred during TOTP secret decryption - TOTP Login", e);
            throw new MfaException(MFA_TOTP_DECRYPTION_FAILED);
        }

        if (!verifyTotp(totpSecretBytes, req.getOtp())) {
            log.warn("TOTP verification failed - TOTP Login");
            throw new MfaException(MFA_TOTP_VERIFICATION_FAILED);
        }

        redisService.delete(redisKey);

        UUID userId = totpLoginEntity.getUserId();

        log.info("Completed Login with TOTP for user {}", userId);

        return ResponseEntity.ok(
                loginHelper.generateLoginCompleteResp(userId, totpLoginEntity.getDeviceId())
        );
    }

    @Transactional
    public ResponseEntity<LoginCompleteResp> totpLoginMfaRecovery(
            String totpCode,
            TotpRecoveryReq req
    ) {
        String redisKey = RedisKeys.totpLogin(tokenHasher.generateSha256(totpCode));
        if (!redisService.exists(redisKey)) {
            log.warn("Token does not exist {} - TOTP Recovery", redisKey);
            throw new MfaException(MFA_TOTP_LOGIN_MISSING_KEY);
        }

        String hashedRecoveryCode = tokenHasher.generateSha256(req.getRecoveryCode());

        TotpLoginEntity totpLoginEntity = redisService.get(redisKey, TotpLoginEntity.class);
        UserEntity userEntity = userDao.findByUserId(totpLoginEntity.getUserId());
        String mfaRecovery = userEntity.getMfaRecoveryCode();

        if (!hashedRecoveryCode.equals(mfaRecovery)) {
            log.warn("TOTP recovery failed");
            throw new MfaException(MFA_TOTP_RECOVERY_CODE_MISMATCH);
        }

        redisService.delete(redisKey);

        TotpEntity totpEntity = userEntity.getTotpEntity();
        totpDao.delete(totpEntity);

        userEntity.setTotpEnabled(false);
        userEntity.setMfaRecoveryCode(null);
        userEntity.setTotpEntity(null);
        userDao.save(userEntity);

        log.info("Completed MFA Recovery Login for user {}", totpLoginEntity.getUserId());

        return ResponseEntity.ok(
                loginHelper.generateLoginCompleteResp(totpLoginEntity.getUserId(), totpLoginEntity.getDeviceId())
        );
    }

    private String createTotpUri(String email, String secret) {
        String appName = "segurapass";
        return UriComponentsBuilder
                .fromUriString("otpauth://totp/")
                .pathSegment(appName + ":" + email)
                .queryParam("secret", secret)
                .queryParam("issuer", appName)
                .queryParam("algorithm", TOTP_ALGORITHM)
                .queryParam("digits", TOTP_DIGITS)
                .queryParam("period", TOTP_PERIOD)
                .build()
                .encode()
                .toUriString();
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    private boolean verifyTotp(byte[] secret, String otp) {
        try {
            if (secret == null || otp == null || !otp.matches("\\d{6}")) {
                return false;
            }

            long currentTimeStep = System.currentTimeMillis() / 1000 / TOTP_PERIOD;

            for (long offset = -1; offset <= 1; offset++) {
                long timeStep = currentTimeStep + offset;

                byte[] counter = ByteBuffer.allocate(Long.BYTES)
                        .putLong(timeStep)
                        .array();

                Mac mac = Mac.getInstance("HmacSHA1");
                mac.init(new SecretKeySpec(secret, "HmacSHA1"));

                byte[] hash = mac.doFinal(counter);

                int offsetValue = hash[hash.length - 1] & 0x0F;

                int binaryCode =
                        ((hash[offsetValue] & 0x7F) << 24)
                                | ((hash[offsetValue + 1] & 0xFF) << 16)
                                | ((hash[offsetValue + 2] & 0xFF) << 8)
                                | (hash[offsetValue + 3] & 0xFF);

                String generatedOtp = String.format("%06d", binaryCode % 1_000_000);
                if (MessageDigest.isEqual(
                        generatedOtp.getBytes(StandardCharsets.US_ASCII),
                        otp.getBytes(StandardCharsets.US_ASCII))) {
                    return true;
                }
            }

            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private String generateNonce(
            UUID userId,
            UUID deviceId,
            MfaType mfaType
    ) {
        TotpNonceEntity nonceEntity = new TotpNonceEntity(
                userId,
                deviceId,
                mfaType
        );
        return nonceHelper.generateNonce(nonceEntity, RedisKeys::mfaNonce);
    }

    private void verifyNonceAndSignature(
            UUID userId,
            UUID deviceId,
            TotpReq req,
            String signature
    ) {
        if (req.getNonce() == null || req.getNonce().isEmpty()) {
            log.warn("TOTP nonce is null or empty");
            throw new MfaException(MFA_NONCE_MISSING);
        }

        String redisKey = RedisKeys.mfaNonce(req.getNonce());
        if (!redisService.exists(redisKey)) {
            log.warn("TOTP nonce could not be found {}", redisKey);
            throw new MfaException(NONCE_NOT_FOUND);
        }

        TotpNonceEntity nonceEntity = redisService.get(redisKey, TotpNonceEntity.class);

        if (nonceEntity == null) {
            log.warn("Write entity is null");
            throw new MfaException(NONCE_ERROR);
        }
        if (!nonceEntity.getUserId().equals(userId)) {
            log.warn("Write entity user ID mismatch");
            throw new MfaException(NONCE_ERROR);
        }
        if (!nonceEntity.getDeviceId().equals(deviceId)) {
            log.warn("Write entity device ID mismatch");
            throw new MfaException(NONCE_ERROR);
        }
        if (!nonceEntity.getMfaType().equals(req.getMfaType())) {
            log.warn("Write entity MFA type mismatch");
            throw new MfaException(NONCE_ERROR);
        }

        try {
            PublicKey publicKey = signatureService.getPublicKey(userId);
            TotpPayload payload = new TotpPayload(
                    req.getMfaType(),
                    req.getNonce()
            );
            byte[] payloadBytes = objectMapper.writeValueAsBytes(payload);
            boolean verified = signatureService.verifySignature(publicKey, payloadBytes, signature);
            if (!verified) {
                log.warn("Signature could not be verified");
                throw new MfaException(INVALID_SIGNATURE);
            }
            redisService.delete(redisKey);
        } catch (Exception e) {
            log.warn("Exception occurred during signature verification", e);
            throw new MfaException(INVALID_SIGNATURE);
        }
    }

}
