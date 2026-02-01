package com.security.passwordmanager.api.error;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ApiErrorEnum {
    USER_EXISTS(HttpStatus.CONFLICT, "Email is already in use"),
    USER_NOT_EXISTS(HttpStatus.CONFLICT, "User with this email does not exist"),
    USER_EMAIL_INVALID(HttpStatus.CONFLICT, "Email is invalid"),
    USER_EMAIL_UNVERIFIED(HttpStatus.UNAUTHORIZED, "User has not yet verified their email"),
    USER_VERIFICATION_NOT_EXISTS(HttpStatus.CONFLICT, "Could not verify user email, user verification token does not exist"),
    USER_VERIFICATION_EXPIRED(HttpStatus.CONFLICT, "Could not verify user email, user verification token has expired"),
    USER_DELETION_NOT_EXISTS(HttpStatus.CONFLICT, "Could not delete user account, user deletion token does not exist"),
    USER_DELETION_EXPIRED(HttpStatus.CONFLICT, "Could not delete user account, user deletion token has expired"),
    SRP_SESSION_NOT_FOUND(HttpStatus.NOT_FOUND, "SRP session could not be found on server"),
    SRP_SESSION_EXPIRED(HttpStatus.CONFLICT, "SRP session has already expired"),
    SRP_VERIFICATION_FAILED(HttpStatus.CONFLICT, "Login information is incorrect"),
    TOKEN_EXPIRED(HttpStatus.CONFLICT, "Refresh token has expired"),
    TOKEN_VERIFICATION_FAILED(HttpStatus.CONFLICT, "User could not verify refresh token"),
    SESSION_NOT_FOUND(HttpStatus.NOT_FOUND, "Session could not be found"),
    CREDENTIAL_NOT_EXISTS(HttpStatus.NOT_FOUND, "Credential with this identifier does not exist"),
    CREDENTIAL_UPDATE_IV_MISSING(HttpStatus.NOT_ACCEPTABLE, "Credential is missing one or multiple required IV fields");

    private final HttpStatus httpStatus;
    private final String message;

    ApiErrorEnum(HttpStatus httpStatus, String message) {
        this.httpStatus = httpStatus;
        this.message = message;
    }
}
