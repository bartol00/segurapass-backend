package com.security.passwordmanager.api.credentials;

import lombok.Data;

@Data
public class CredentialsReq {
    private String website;
    private String username;
    private String password;
    private String iv;
}
