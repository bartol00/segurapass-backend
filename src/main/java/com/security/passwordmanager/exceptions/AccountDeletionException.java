package com.security.passwordmanager.exceptions;

import com.security.passwordmanager.exceptions.enums.ErrorEnum;
import lombok.Getter;

@Getter
public class AccountDeletionException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public AccountDeletionException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
