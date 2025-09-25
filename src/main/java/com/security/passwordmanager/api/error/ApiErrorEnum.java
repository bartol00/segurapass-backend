package com.security.passwordmanager.api.error;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ApiErrorEnum {
    USER_EXISTS(HttpStatus.CONFLICT, "Email is already in use");

    private final HttpStatus httpStatus;
    private final String message;

    ApiErrorEnum(HttpStatus httpStatus, String message) {
        this.httpStatus = httpStatus;
        this.message = message;
    }
}
