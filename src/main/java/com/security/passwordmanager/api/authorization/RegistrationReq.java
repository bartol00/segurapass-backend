package com.security.passwordmanager.api.authorization;

import lombok.Data;

import java.util.UUID;

@Data
public class RegistrationReq {
    private String email;
    private String publicKeyPem;
    private String encryptedPrivateKey;
    private String keyIv;
    private String keySalt;
    private UUID deviceId;
}
