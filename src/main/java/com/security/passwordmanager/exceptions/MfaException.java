package com.security.passwordmanager.exceptions;

import lombok.Getter;

@Getter
public class MfaException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public MfaException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
