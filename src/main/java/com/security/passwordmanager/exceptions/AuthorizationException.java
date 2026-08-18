package com.security.passwordmanager.exceptions;

import com.security.passwordmanager.exceptions.enums.ErrorEnum;
import lombok.Getter;

@Getter
public class AuthorizationException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public AuthorizationException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
