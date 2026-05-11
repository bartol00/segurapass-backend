package com.security.passwordmanager.exceptions;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorEnum {
    USER_EXISTS(HttpStatus.CONFLICT, "Email is already in use"),
    USER_NOT_EXISTS(HttpStatus.CONFLICT, "User with this email does not exist"),
    USER_EMAIL_INVALID(HttpStatus.CONFLICT, "Email is invalid"),
    USER_VERIFICATION_NOT_EXISTS(HttpStatus.CONFLICT, "Could not verify user email, user verification token does not exist"),
    SRP_VERIFICATION_FAILED(HttpStatus.CONFLICT, "Login information is incorrect"),
    CREDENTIAL_NOT_EXISTS(HttpStatus.NOT_FOUND, "Credential with this identifier does not exist"),
    CREDENTIAL_UPDATE_IV_MISSING(HttpStatus.NOT_ACCEPTABLE, "Credential is missing one or multiple required IV fields"),
    PUBLIC_KEY_NOT_READ(HttpStatus.INTERNAL_SERVER_ERROR, "Public key could not be read"),
    TOKEN_NOT_FOUND(HttpStatus.NOT_FOUND, "Token could not be found");

    private final HttpStatus httpStatus;
    private final String message;

    ErrorEnum(HttpStatus httpStatus, String message) {
        this.httpStatus = httpStatus;
        this.message = message;
    }
}
