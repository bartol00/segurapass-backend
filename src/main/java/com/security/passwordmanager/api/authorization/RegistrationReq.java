package com.security.passwordmanager.api.authorization;

import lombok.Data;

import java.util.UUID;

@Data
public class RegistrationReq {
    private String email;
    private String saltAuth;
    private String verifier;
    private String saltKey;
    private UUID deviceId;
}
