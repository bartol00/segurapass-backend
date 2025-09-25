package com.security.passwordmanager.api.authorization;

import lombok.Data;

@Data
public class LoginCompleteResp {
    private String accessToken;
    private String refreshToken;
}
