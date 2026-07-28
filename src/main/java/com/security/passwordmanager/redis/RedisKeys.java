package com.security.passwordmanager.redis;

public final class RedisKeys {

    public static String emailUnverified(String tokenHash) {
        return "segurapass:email_unverified:%s".formatted(tokenHash);
    }

    public static String emailUnverifiedEmail(String emailHash) {
        return "segurapass:email_unverified:email:%s".formatted(emailHash);
    }

    public static String srp(String userId, String deviceId) {
        return "segurapass:srp:%s:%s".formatted(userId, deviceId);
    }

    public static String accountDeletion(String userId, String deviceId) {
        return "segurapass:account_deletion:%s:%s".formatted(userId, deviceId);
    }

    public static String passwordChange(String userId, String deviceId) {
        return "segurapass:password_change:%s:%s".formatted(userId, deviceId);
    }

    public static String session(String tokenHash) {
        return "segurapass:session:%s".formatted(tokenHash);
    }

    public static String emailDeletion(String tokenHash) {
        return "segurapass:email_deletion:%s".formatted(tokenHash);
    }

    public static String emailDeletionEmail(String emailHash) {
        return "segurapass:email_deletion:email:%s".formatted(emailHash);
    }

    public static String credentialsNonce(String nonce) {
        return "segurapass:credentials_nonce:%s".formatted(nonce);
    }

    public static String userPublicKey(String userId) {
        return "segurapass:user_public_key:%s".formatted(userId);
    }

    public static String rateLimitIp(String ip, String pattern) {
        return "segurapass:rate_limit:ip:%s:%s".formatted(ip, pattern);
    }

    public static String rateLimitUserId(String userId, String pattern) {
        return "segurapass:rate_limit:user:%s:%s".formatted(userId, pattern);
    }

}
