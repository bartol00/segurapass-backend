package com.security.passwordmanager.api.authorization;

import lombok.Data;

import java.util.UUID;

@Data
public class RefreshReq {
    private String email;
    private UUID deviceId;
    private String refreshToken;
}
