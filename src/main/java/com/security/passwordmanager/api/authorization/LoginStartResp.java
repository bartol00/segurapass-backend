package com.security.passwordmanager.api.authorization;

import lombok.Data;

import java.util.UUID;

@Data
public class LoginStartResp {
    private String encryptedPrivateKey;
    private String keyIv;
    private UUID nonce;
}
