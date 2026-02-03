package com.security.passwordmanager.api.deletion;

import lombok.Data;

@Data
public class AuthorizedDeletionStartResp {
    private String B;
    private String saltAuth;
}
