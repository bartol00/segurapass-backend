package com.security.passwordmanager.api.authorization;

import lombok.Data;

@Data
public class LoginStartReq {
    private String email;
    private String A;
}
