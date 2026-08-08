package com.security.passwordmanager.service.mfa;

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
import com.security.passwordmanager.redis.entities.TotpNonceEntity;
import com.security.passwordmanager.redis.entities.TotpRedisEntity;
import com.security.passwordmanager.redis.entities.UserPublicKeyEntity;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import xyz.segurapass.api.credentials.NonceResp;
import xyz.segurapass.api.mfa.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

import static com.security.passwordmanager.exceptions.ErrorEnum.*;
import static com.security.passwordmanager.exceptions.ErrorEnum.INVALID_SIGNATURE;
import static com.security.passwordmanager.exceptions.ErrorEnum.NONCE_ERROR;

@Service
@RequiredArgsConstructor
@Slf4j
public class TotpService {

    private final TokenGenerator tokenGenerator;
    private final TokenHasher tokenHasher;
    private final RedisService redisService;
    private final EncryptionService encryptionService;

    private final UserDao userDao;
    private final TotpDao totpDao;

    private final ObjectMapper objectMapper;

    private final String TOTP_ALGORITHM = "SHA1";
    private final int TOTP_DIGITS = 6;
    private final int TOTP_PERIOD = 30;


    public ResponseEntity<NonceResp> addTotpStart(UUID userId, UUID deviceId) {
        if (totpDao.findByUserEntity_UserId(userId) != null) {
            throw new MfaException(MFA_TOTP_ALREADY_EXISTS);
        }
        String nonce = generateNonce(userId, deviceId, MfaType.TOTP_ADD);
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
            throw new MfaException(MFA_TOTP_ENCRYPTION_FAILED);
        }

        String redisKey = RedisKeys.totpVerification(userId.toString(), deviceId.toString());
        redisService.save(redisKey, totpRedisEntity, Duration.of(10, ChronoUnit.MINUTES));

        return ResponseEntity.ok(new TotpResp(totpUri));
    }

    public ResponseEntity<NonceResp> removeTotpStart(UUID userId, UUID deviceId) {
        if (totpDao.findByUserEntity_UserId(userId) == null) {
            throw new MfaException(MFA_TOTP_NOT_EXISTS);
        }
        String nonce = generateNonce(userId, deviceId, MfaType.TOTP_REMOVE);
        return ResponseEntity.ok(new NonceResp(nonce));
    }

    public ResponseEntity<Void> removeTotpEnd(
            TotpReq req,
            UUID userId,
            UUID deviceId,
            String signature
    ) {
        verifyNonceAndSignature(userId, deviceId, req, signature);
        totpDao.deleteByUserEntity_UserId(userId);
        return ResponseEntity.ok(null);
    }

    @Transactional
    public ResponseEntity<TotpVerifyResp> verifyTotp(
            TotpVerifyReq req,
            UUID userId,
            UUID deviceId
    ) {
        if (totpDao.findByUserEntity_UserId(userId) != null) {
            throw new MfaException(MFA_TOTP_ALREADY_EXISTS);
        }

        String redisKey = RedisKeys.totpVerification(userId.toString(), deviceId.toString());
        TotpRedisEntity totpRedisEntity = redisService.get(redisKey, TotpRedisEntity.class);

        byte[] totpSecret;
        try {
            totpSecret = encryptionService.decryptTotpSecret(
                    totpRedisEntity.getEncryptedTotpSecret(),
                    totpRedisEntity.getIv()
            );
        } catch (Exception e) {
            throw new MfaException(MFA_TOTP_DECRYPTION_FAILED);
        }

        if (!verifyTotp(totpSecret, req.getOtp())) {
            throw new MfaException(MFA_TOTP_VERIFICATION_FAILED);
        }

        UserEntity userEntity = userDao.findByUserId(userId);

        TotpEntity totpEntity = new TotpEntity();
        totpEntity.setEncryptedToken(totpRedisEntity.getEncryptedTotpSecret());
        totpEntity.setTokenIv(totpRedisEntity.getIv());
        totpEntity.setCreatedAt(Instant.now());
        totpEntity.setUserEntity(userEntity);
        totpDao.save(totpEntity);

        String mfaRecoveryCode = tokenGenerator.generateRandomToken(32);
        String recoveryHash = tokenHasher.generateSha256(mfaRecoveryCode);

        userEntity.setMfaEnabled(true);
        userEntity.setMfaRecoveryCode(recoveryHash);
        userDao.save(userEntity);

        redisService.delete(redisKey);

        return ResponseEntity.ok(new TotpVerifyResp(mfaRecoveryCode));
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

    private String generateNonce(UUID userId, UUID deviceId, MfaType mfaType) {
        String nonce = tokenGenerator.generateRandomToken(48);

        String redisKey = RedisKeys.mfaNonce(nonce);
        TotpNonceEntity writeEntity = new TotpNonceEntity(
                userId,
                deviceId,
                mfaType
        );

        redisService.save(redisKey, writeEntity, Duration.of(60, ChronoUnit.SECONDS));

        return nonce;
    }

    private void verifyNonceAndSignature(
            UUID userId,
            UUID deviceId,
            TotpReq req,
            String signature
    ) {
        if (req.getNonce() == null || req.getNonce().isEmpty()) {
            throw new MfaException(MFA_NONCE_MISSING);
        }

        String redisKey = RedisKeys.mfaNonce(req.getNonce());
        if (!redisService.exists(redisKey)) {
            throw new MfaException(NONCE_NOT_FOUND);
        }

        TotpNonceEntity writeEntity = redisService.get(redisKey, TotpNonceEntity.class);

        if (writeEntity == null) {
            throw new MfaException(NONCE_ERROR);
        }
        if (!writeEntity.getUserId().equals(userId)) {
            throw new MfaException(NONCE_ERROR);
        }
        if (!writeEntity.getDeviceId().equals(deviceId)) {
            throw new MfaException(NONCE_ERROR);
        }
        if (!writeEntity.getMfaType().equals(req.getMfaType())) {
            throw new MfaException(NONCE_ERROR);
        }

        try {
            PublicKey publicKey = getPublicKey(userId);
            TotpPayload payload = new TotpPayload(
                    req.getMfaType(),
                    req.getNonce()
            );
            byte[] payloadBytes = objectMapper.writeValueAsBytes(payload);
            boolean verified = verifySignature(publicKey, payloadBytes, signature);
            if (!verified) {
                throw new MfaException(INVALID_SIGNATURE);
            }
            redisService.delete(redisKey);
        } catch (Exception e) {
            throw new MfaException(INVALID_SIGNATURE);
        }
    }

    private PublicKey getPublicKey(UUID userId) throws Exception {
        String redisKey = RedisKeys.userPublicKey(userId.toString());
        KeyFactory factory = KeyFactory.getInstance("Ed25519");

        if (redisService.exists(redisKey)) {
            UserPublicKeyEntity userPublicKeyEntity = redisService.get(redisKey, UserPublicKeyEntity.class);
            return factory.generatePublic(
                    new X509EncodedKeySpec(userPublicKeyEntity.getPublicKeyBytes())
            );
        } else {
            String publicKeyStr = userDao.findByUserId(userId).getPublicSigningKey();
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyStr);

            UserPublicKeyEntity userPublicKeyEntity = new UserPublicKeyEntity(keyBytes);
            redisService.save(redisKey, userPublicKeyEntity, Duration.of(10, ChronoUnit.MINUTES));

            return factory.generatePublic(
                    new X509EncodedKeySpec(keyBytes)
            );
        }
    }

    private boolean verifySignature(
            PublicKey publicKey,
            byte[] payload,
            String signatureBase64
    ) throws Exception {
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(publicKey);
        signature.update(payload);

        return signature.verify(signatureBytes);
    }

}
