package com.security.passwordmanager.api.error;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ApiErrorEnum {
    USER_EXISTS(HttpStatus.CONFLICT, "Email is already in use"),
    USER_NOT_EXISTS(HttpStatus.CONFLICT, "User with this email does not exist"),
    SRP_SESSION_NOT_FOUND(HttpStatus.NOT_FOUND, "SRP session could not be found on server"),
    SRP_VERIFICATION_FAILED(HttpStatus.CONFLICT, "SRP verification failed"),
    TOKEN_EXPIRED(HttpStatus.CONFLICT, "Refresh token has expired"),
    TOKEN_VERIFICATION_FAILED(HttpStatus.CONFLICT, "User could not verify refresh token"),
    CREDENTIAL_NOT_EXISTS(HttpStatus.NOT_FOUND, "Credential with this identifier does not exist"),
    CREDENTIAL_UPDATE_IV_MISSING(HttpStatus.NOT_ACCEPTABLE, "Credential is missing one or both required IV fields");

    private final HttpStatus httpStatus;
    private final String message;

    ApiErrorEnum(HttpStatus httpStatus, String message) {
        this.httpStatus = httpStatus;
        this.message = message;
    }
}
