package com.security.passwordmanager.api.credentials;

import lombok.Data;

import java.time.Instant;
import java.util.UUID;

@Data
public class CredentialsResp {
    private UUID credentialsId;
    private String website;
    private String username;
    private String password;
    private String ivEmail;
    private String ivPassword;
    private Instant lastUpdated;
}
