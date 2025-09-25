package com.security.passwordmanager.api.authorization;

import lombok.Data;

@Data
public class LoginCompleteReq {
    private String email;
    private String deviceId;
    private String signedNonce;
}
