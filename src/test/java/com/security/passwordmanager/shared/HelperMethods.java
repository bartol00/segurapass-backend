package com.security.passwordmanager.shared;

import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.credentials.CredentialsEntity;
import com.security.passwordmanager.redis.entities.UserRedisEntity;
import xyz.segurapass.api.authorization.LoginCompleteReq;
import xyz.segurapass.api.authorization.LoginStartReq;
import xyz.segurapass.api.authorization.RefreshReq;
import xyz.segurapass.api.authorization.RegistrationReq;
import xyz.segurapass.api.credentials.CredentialsReq;
import xyz.segurapass.api.deletion.AuthorizedDeletionCompleteReq;
import xyz.segurapass.api.deletion.AuthorizedDeletionStartReq;
import xyz.segurapass.api.deletion.EmailDeletionStartReq;
import xyz.segurapass.api.password.PasswordChangeCompleteReq;
import xyz.segurapass.api.password.PasswordChangeStartReq;

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
        userEntity.setSaltAuth(UUID.randomUUID().toString());
        userEntity.setVerifier("verifier");
        userEntity.setVaultKey("vaultKey");
        userEntity.setIvVaultKey("ivVaultKey");
        userEntity.setSaltKey(UUID.randomUUID().toString());
        userEntity.setSaltHkdf(UUID.randomUUID().toString());
        userEntity.setPrivateSigningKey("privateSigningKey");
        userEntity.setPublicSigningKey("publicSigningKey");
        userEntity.setIvPrivateSigningKey("ivPrivateSigningKey");
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
                "saltAuth",
                "verifier",
                "vaultKey",
                "ivVaultKey",
                "saltKey",
                "saltHkdf",
                "privateSigningKey",
                "publicSigningKey",
                "privateSigningKeyIv",
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
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                Instant.now()
        );
    }
    
    // CredentialsServiceIT helper methods
    public static CredentialsReq generateCredentialsReq() {
        CredentialsReq credentialsReq = new CredentialsReq();
        credentialsReq.setWebsite("unique website");
        credentialsReq.setUsername("unique username");
        credentialsReq.setPassword("unique password");
        credentialsReq.setIvWebsite(UUID.randomUUID().toString());
        credentialsReq.setIvUsername(UUID.randomUUID().toString());
        credentialsReq.setIvPassword(UUID.randomUUID().toString());
        return credentialsReq;
    }

    public static CredentialsEntity generateCredentialsEntity(UserEntity userEntity) {
        CredentialsEntity credentialsEntity = new CredentialsEntity();
        credentialsEntity.setCredentialsId(UUID.randomUUID());
        credentialsEntity.setWebsite(UUID.randomUUID().toString());
        credentialsEntity.setUsername(UUID.randomUUID().toString());
        credentialsEntity.setPassword(UUID.randomUUID().toString());
        credentialsEntity.setIvWebsite(UUID.randomUUID().toString());
        credentialsEntity.setIvUsername(UUID.randomUUID().toString());
        credentialsEntity.setIvPassword(UUID.randomUUID().toString());
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
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString()
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

}
