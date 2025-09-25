package com.security.passwordmanager.api.authorization;

import lombok.Data;

@Data
public class LoginStartResp {
    private String encryptedPrivateKey;
    private String keyIv;
    private String nonce;
}
