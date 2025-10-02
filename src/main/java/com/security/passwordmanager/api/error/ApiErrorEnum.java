package com.security.passwordmanager.api.error;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ApiErrorEnum {
    USER_EXISTS(HttpStatus.CONFLICT, "Email is already in use"),
    USER_NOT_EXISTS(HttpStatus.CONFLICT, "User with this email does not exist"),
    NONCE_EXPIRED(HttpStatus.CONFLICT, "Nonce has expired"),
    NONCE_VERIFICATION_FAILED(HttpStatus.UNAUTHORIZED, "User could not verify nonce"),
    NONCE_VERIFICATION_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "An error occurred during nonce verification"),
    TOKEN_EXPIRED(HttpStatus.CONFLICT, "Refresh token has expired"),
    TOKEN_VERIFICATION_FAILED(HttpStatus.CONFLICT, "User could not verify refresh token"),
    CREDENTIAL_NOT_EXISTS(HttpStatus.NOT_FOUND, "Credential with this identifier does not exist");

    private final HttpStatus httpStatus;
    private final String message;

    ApiErrorEnum(HttpStatus httpStatus, String message) {
        this.httpStatus = httpStatus;
        this.message = message;
    }
}
