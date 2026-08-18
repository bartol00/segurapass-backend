package com.security.passwordmanager.exceptions;

import com.security.passwordmanager.exceptions.enums.ErrorEnum;
import lombok.Getter;

@Getter
public class PasswordChangeException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public PasswordChangeException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
