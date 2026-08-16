package com.security.passwordmanager.service.mfa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.passwordmanager.config.JwtService;
import com.security.passwordmanager.exceptions.MfaException;
import com.security.passwordmanager.helpers.EncryptionService;
import com.security.passwordmanager.helpers.TokenGenerator;
import com.security.passwordmanager.helpers.TokenHasher;
import com.security.passwordmanager.model.audit.AuditAction;
import com.security.passwordmanager.model.audit.AuditLogDao;
import com.security.passwordmanager.model.audit.AuditLogEntity;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.mfa.TotpDao;
import com.security.passwordmanager.model.mfa.TotpEntity;
import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.*;
import jakarta.transaction.Transactional;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import xyz.segurapass.api.authorization.LoginCompleteResp;
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
import java.util.HashMap;
import java.util.Map;
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
    private final JwtService jwtService;

    private final UserDao userDao;
    private final TotpDao totpDao;
    private final AuditLogDao auditLogDao;

    private final ObjectMapper objectMapper;

    @Getter
    private final String TOTP_ALGORITHM = "SHA1";
    @Getter
    private final int TOTP_DIGITS = 6;
    @Getter
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

        byte[] totpSecretBytes;
        try {
            totpSecretBytes = encryptionService.decryptTotpSecret(
                    totpRedisEntity.getTotpSecretBytes(),
                    totpRedisEntity.getTotpSecretIv()
            );
        } catch (Exception e) {
            throw new MfaException(MFA_TOTP_DECRYPTION_FAILED);
        }

        if (!verifyTotp(totpSecretBytes, req.getOtp())) {
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

        return ResponseEntity.ok(new TotpVerifyResp(mfaRecoveryCode));
    }

    @Transactional
    public ResponseEntity<LoginCompleteResp> totpLogin(
            String totpCode,
            TotpVerifyReq req
    ) {
        String redisKey = RedisKeys.totpLogin(tokenHasher.generateSha256(totpCode));
        if (!redisService.exists(redisKey)) {
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
            throw new MfaException(MFA_TOTP_DECRYPTION_FAILED);
        }

        if (!verifyTotp(totpSecretBytes, req.getOtp())) {
            throw new MfaException(MFA_TOTP_VERIFICATION_FAILED);
        }

        redisService.delete(redisKey);

        return ResponseEntity.ok(
                generateLoginCompleteResp(totpLoginEntity.getUserId(), totpLoginEntity.getDeviceId())
        );
    }

    @Transactional
    public ResponseEntity<LoginCompleteResp> totpLoginMfaRecovery(
            String totpCode,
            TotpRecoveryReq req
    ) {
        String redisKey = RedisKeys.totpLogin(tokenHasher.generateSha256(totpCode));
        if (!redisService.exists(redisKey)) {
            throw new MfaException(MFA_TOTP_LOGIN_MISSING_KEY);
        }

        String hashedRecoveryCode = tokenHasher.generateSha256(req.getRecoveryCode());

        TotpLoginEntity totpLoginEntity = redisService.get(redisKey, TotpLoginEntity.class);
        UserEntity userEntity = userDao.findByUserId(totpLoginEntity.getUserId());
        String mfaRecovery = userEntity.getMfaRecoveryCode();

        if (!hashedRecoveryCode.equals(mfaRecovery)) {
            throw new MfaException(MFA_TOTP_RECOVERY_CODE_MISMATCH);
        }

        redisService.delete(redisKey);

        TotpEntity totpEntity = userEntity.getTotpEntity();
        totpDao.delete(totpEntity);

        userEntity.setTotpEnabled(false);
        userEntity.setMfaRecoveryCode(null);
        userEntity.setTotpEntity(null);
        userDao.save(userEntity);

        return ResponseEntity.ok(
                generateLoginCompleteResp(totpLoginEntity.getUserId(), totpLoginEntity.getDeviceId())
        );
    }

    private LoginCompleteResp generateLoginCompleteResp(UUID userId, UUID deviceId) {
        UserEntity userEntity = userDao.findByUserId(userId);
        userEntity.setLastLogin(Instant.now());
        userDao.save(userEntity);

        String refreshToken = tokenGenerator.generateRefreshToken(32);
        Instant refreshExpiry = Instant.now().plus(30, ChronoUnit.MINUTES);

        String tokenHash = tokenHasher.generateSha256(refreshToken);
        SessionRedisEntity sessionRedisEntity = new SessionRedisEntity(
                userEntity.getUserId(),
                deviceId
        );
        redisService.save(
                RedisKeys.session(tokenHash),
                sessionRedisEntity,
                Duration.between(Instant.now(), refreshExpiry)
        );

        AuditLogEntity auditLogEntity = new AuditLogEntity();
        auditLogEntity.setUserId(userEntity.getUserId());
        auditLogEntity.setTimestamp(Instant.now());
        auditLogEntity.setAction(AuditAction.LOGIN_SUCCESS);
        auditLogEntity.setIpAddress(MDC.get("clientIp"));
        auditLogEntity.setSuccess(true);
        auditLogDao.save(auditLogEntity);

        LoginCompleteResp resp = new LoginCompleteResp(
                null,
                userEntity.getVaultKeyBytes(),
                userEntity.getIvVaultKeyBytes(),
                userEntity.getSaltKeyBytes(),
                userEntity.getSaltHkdfBytes(),
                userEntity.getPrivateSigningKeyBytes(),
                userEntity.getPublicSigningKeyBytes(),
                userEntity.getIvPrivateSigningKeyBytes(),
                generateJwt(userEntity.getUserId(), deviceId),
                refreshToken,
                refreshExpiry
        );

        log.info(
                "Login Complete for user (email hash): {} - Service",
                tokenHasher.generateSha256Email(userEntity.getEmail())
        );

        return resp;
    }

    private String generateJwt(UUID userId, UUID deviceId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("deviceId", deviceId);
        return jwtService.generateToken(userId.toString(), claims, 180);
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
        TotpNonceEntity nonceEntity = new TotpNonceEntity(
                userId,
                deviceId,
                mfaType
        );

        redisService.save(redisKey, nonceEntity, Duration.of(60, ChronoUnit.SECONDS));

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

        TotpNonceEntity nonceEntity = redisService.get(redisKey, TotpNonceEntity.class);

        if (nonceEntity == null) {
            throw new MfaException(NONCE_ERROR);
        }
        if (!nonceEntity.getUserId().equals(userId)) {
            throw new MfaException(NONCE_ERROR);
        }
        if (!nonceEntity.getDeviceId().equals(deviceId)) {
            throw new MfaException(NONCE_ERROR);
        }
        if (!nonceEntity.getMfaType().equals(req.getMfaType())) {
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
            byte[] publicKeyBytes = userDao.findByUserId(userId).getPublicSigningKeyBytes();

            UserPublicKeyEntity userPublicKeyEntity = new UserPublicKeyEntity(publicKeyBytes);
            redisService.save(redisKey, userPublicKeyEntity, Duration.of(10, ChronoUnit.MINUTES));

            return factory.generatePublic(
                    new X509EncodedKeySpec(publicKeyBytes)
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
