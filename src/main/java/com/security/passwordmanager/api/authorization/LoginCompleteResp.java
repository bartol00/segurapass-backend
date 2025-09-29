package com.security.passwordmanager.api.authorization;

import lombok.Data;

import java.time.Instant;

@Data
public class LoginCompleteResp {
    private String accessToken;
    private String refreshToken;
    private Instant refreshTokenExpiryTime;
}
