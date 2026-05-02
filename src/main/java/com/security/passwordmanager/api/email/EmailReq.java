package com.security.passwordmanager.api.email;

import lombok.Data;

@Data
public class EmailReq {
    private String to;
    private String subject;
    private String text;
    private String html;
}
