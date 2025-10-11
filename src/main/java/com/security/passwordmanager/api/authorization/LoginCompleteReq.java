package com.security.passwordmanager.api.authorization;

import lombok.Data;

import java.util.UUID;

@Data
public class LoginCompleteReq {
    private String email;
    private UUID deviceId;
    private String M1;
}
