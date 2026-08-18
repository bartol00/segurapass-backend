package com.security.passwordmanager.exceptions;

import com.security.passwordmanager.exceptions.enums.ErrorEnum;
import lombok.Getter;

@Getter
public class MfaException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public MfaException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
