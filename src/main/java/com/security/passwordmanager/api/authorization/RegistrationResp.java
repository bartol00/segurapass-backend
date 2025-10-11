package com.security.passwordmanager.api.authorization;

import lombok.Data;

import java.time.Instant;

@Data
public class RegistrationResp {
    private String accessToken;
    private String refreshToken;
    private Instant refreshTokenExpiryTime;
}
