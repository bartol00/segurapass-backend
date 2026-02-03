package com.security.passwordmanager.api.deletion;

import lombok.Data;

import java.util.UUID;

@Data
public class AuthorizedDeletionStartReq {
    private UUID deviceId;
    private String A;
}
