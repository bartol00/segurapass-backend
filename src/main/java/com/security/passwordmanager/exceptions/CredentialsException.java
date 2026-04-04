package com.security.passwordmanager.exceptions;

import lombok.Getter;

@Getter
public class CredentialsException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public CredentialsException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
