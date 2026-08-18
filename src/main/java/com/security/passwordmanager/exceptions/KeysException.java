package com.security.passwordmanager.exceptions;

import com.security.passwordmanager.exceptions.enums.ErrorEnum;
import lombok.Getter;

@Getter
public class KeysException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public KeysException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
