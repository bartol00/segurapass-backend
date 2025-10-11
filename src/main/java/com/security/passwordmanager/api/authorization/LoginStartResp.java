package com.security.passwordmanager.api.authorization;

import lombok.Data;

@Data
public class LoginStartResp {
    private String B;
    private String saltAuth;
}
