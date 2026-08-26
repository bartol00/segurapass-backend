package com.security.passwordmanager.shared;

import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.credentials.CredentialsEntity;
import com.security.passwordmanager.model.mfa.TotpEntity;
import com.security.passwordmanager.redis.entities.TotpNonceEntity;
import com.security.passwordmanager.redis.entities.UserRedisEntity;
import xyz.segurapass.api.authorization.LoginCompleteReq;
import xyz.segurapass.api.authorization.LoginStartReq;
import xyz.segurapass.api.authorization.RefreshReq;
import xyz.segurapass.api.authorization.RegistrationReq;
import xyz.segurapass.api.credentials.CredentialsReq;
import xyz.segurapass.api.deletion.AuthorizedDeletionCompleteReq;
import xyz.segurapass.api.deletion.AuthorizedDeletionStartReq;
import xyz.segurapass.api.deletion.EmailDeletionStartReq;
import xyz.segurapass.api.mfa.MfaType;
import xyz.segurapass.api.password.PasswordChangeCompleteReq;
import xyz.segurapass.api.password.PasswordChangeStartReq;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

public class HelperMethods {

    public static final String email = "user@gmail.com";
    public static final UUID userId = UUID.fromString("14bd3b93-3413-4108-a68b-416cb71e6c70");
    public static final UUID deviceId = UUID.fromString("aa621bf6-83c5-4eb3-b503-8d5650ecd5e0");

    // general helper methods
    public static UserEntity generateUserEntity() {
        UserEntity userEntity = new UserEntity();
        userEntity.setUserId(userId);
        userEntity.setEmail("user@gmail.com");
        userEntity.setSaltAuthBytes(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        userEntity.setVerifier("verifier");
        userEntity.setVaultKeyBytes("vaultKey".getBytes(StandardCharsets.UTF_8));
        userEntity.setIvVaultKeyBytes("ivVaultKey".getBytes(StandardCharsets.UTF_8));
        userEntity.setSaltKeyBytes(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        userEntity.setSaltHkdfBytes(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        userEntity.setPrivateSigningKeyBytes("privateSigningKey".getBytes(StandardCharsets.UTF_8));
        userEntity.setPublicSigningKeyBytes("publicSigningKey".getBytes(StandardCharsets.UTF_8));
        userEntity.setIvPrivateSigningKeyBytes("ivPrivateSigningKey".getBytes(StandardCharsets.UTF_8));
        return userEntity;
    }

    // AccountDeletionServiceIT helper methods
    public static AuthorizedDeletionStartReq generateAuthorizedDeletionStartReq(UUID deviceId) {
        return new AuthorizedDeletionStartReq(
                deviceId,
                "publicA"
        );
    }

    public static AuthorizedDeletionCompleteReq generateAuthorizedDeletionCompleteReq(UUID deviceId, String M1) {
        return new AuthorizedDeletionCompleteReq(
                deviceId,
                M1
        );
    }

    public static EmailDeletionStartReq generateEmailDeletionStartReq(String email) {
        return new EmailDeletionStartReq(email);
    }

    // AuthorizationServiceIT helper methods
    public static RegistrationReq generateRegistrationReq(String email) {
        return new RegistrationReq(
                email,
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID()
        );
    }

    public static LoginStartReq generateLoginStartReq(String email) {
        return new LoginStartReq(
                email,
                UUID.randomUUID(),
                "publicA"
        );
    }

    public static LoginCompleteReq generateLoginCompleteReq(String email, String M1) {
        return new LoginCompleteReq(
                email,
                UUID.randomUUID(),
                M1
        );
    }

    public static RefreshReq generateRefreshReq(String refreshToken) {
        return new RefreshReq(refreshToken);
    }

    public static UserRedisEntity generateUserRedisEntity(UUID userId, String email) {
        return new UserRedisEntity(
                userId,
                email,
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                Instant.now()
        );
    }
    
    // CredentialsServiceIT helper methods
    public static CredentialsReq generateCredentialsReq() {
        CredentialsReq credentialsReq = new CredentialsReq();
        credentialsReq.setWebsiteBytes("unique website".getBytes(StandardCharsets.UTF_8));
        credentialsReq.setUsernameBytes("unique username".getBytes(StandardCharsets.UTF_8));
        credentialsReq.setPasswordBytes("unique password".getBytes(StandardCharsets.UTF_8));
        credentialsReq.setIvWebsiteBytes(new byte[12]);
        credentialsReq.setIvUsernameBytes(new byte[12]);
        credentialsReq.setIvPasswordBytes(new byte[12]);
        return credentialsReq;
    }

    public static CredentialsEntity generateCredentialsEntity(UserEntity userEntity) {
        CredentialsEntity credentialsEntity = new CredentialsEntity();
        credentialsEntity.setCredentialsId(UUID.randomUUID());
        credentialsEntity.setWebsiteBytes(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        credentialsEntity.setUsernameBytes(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        credentialsEntity.setPasswordBytes(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        credentialsEntity.setIvWebsiteBytes(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        credentialsEntity.setIvUsernameBytes(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        credentialsEntity.setIvPasswordBytes(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        credentialsEntity.setCreatedAt(Instant.now());
        credentialsEntity.setLastUpdated(Instant.now());
        credentialsEntity.setUserEntity(userEntity);
        return credentialsEntity;
    }

    // PasswordChangeIT helper methods
    public static PasswordChangeStartReq generatePasswordChangeStartReq(UUID deviceId) {
        return new PasswordChangeStartReq(
                deviceId,
                "publicA"
        );
    }

    public static PasswordChangeCompleteReq generatePasswordChangeCompleteReq(UUID deviceId, String M1) {
        return new PasswordChangeCompleteReq(
                deviceId,
                M1,
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8),
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)
        );
    }

    // RateLimitIT helper methods
    public static String loginStartRequestJson() {
        return """
        {
            "email": "test@test.com",
            "deviceId": "1f13c83d-473d-459c-809c-b64e76bfae0d",
            "A": "randomA"
        }
        """;
    }

    public static String generateJwt(String token) {
        return String.format("Bearer %s", token);
    }

    // TotpServiceIT helper methods
    public static TotpEntity generateTotpEntity(
            UserEntity userEntity,
            byte[] totpSecretBytes,
            byte[] totpSecretIv
    ) {
        TotpEntity totpEntity = generateTotpEntity(userEntity);
        totpEntity.setTotpTokenBytes(totpSecretBytes);
        totpEntity.setTotpTokenIv(totpSecretIv);
        return totpEntity;
    }

    public static TotpEntity generateTotpEntity(UserEntity userEntity) {
        TotpEntity totpEntity = new TotpEntity();
        totpEntity.setTotpTokenBytes(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        totpEntity.setTotpTokenIv(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        totpEntity.setCreatedAt(Instant.now());
        totpEntity.setUserEntity(userEntity);
        return totpEntity;
    }

    public static TotpNonceEntity generateTotpNonceEntity(MfaType mfaType) {
        TotpNonceEntity totpNonceEntity = new TotpNonceEntity();
        totpNonceEntity.setUserId(UUID.randomUUID());
        totpNonceEntity.setDeviceId(UUID.randomUUID());
        totpNonceEntity.setMfaType(mfaType);
        return totpNonceEntity;
    }

}
