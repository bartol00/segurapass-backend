package com.security.passwordmanager.exceptions.enums;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorEnum {
    USER_EXISTS(HttpStatus.CONFLICT, "Email is already in use"),
    USER_NOT_EXISTS(HttpStatus.CONFLICT, "User with this email does not exist"),
    USER_EMAIL_INVALID(HttpStatus.CONFLICT, "Email is invalid"),
    USER_VERIFICATION_NOT_EXISTS(HttpStatus.CONFLICT, "Could not verify user email, user verification token does not exist"),
    EMAIL_VERIFICATION_OFF(HttpStatus.CONFLICT, "Email verification is not enabled on this server"),
    SRP_VERIFICATION_FAILED(HttpStatus.CONFLICT, "Login information is incorrect"),
    CREDENTIAL_NOT_EXISTS(HttpStatus.NOT_FOUND, "Credential with this identifier does not exist"),
    CREDENTIAL_UPDATE_IV_MISSING(HttpStatus.NOT_ACCEPTABLE, "Credential is missing one or multiple required IV fields"),
    CREDENTIAL_NONCE_MISSING(HttpStatus.NOT_ACCEPTABLE, "Credential is missing the required Nonce field"),
    CREDENTIAL_REQ_BYTES_TOO_LONG(HttpStatus.NOT_ACCEPTABLE, "Credential is too large"),
    CREDENTIAL_REQ_IV_BYTES_LEN_ERROR(HttpStatus.NOT_ACCEPTABLE, "IV is not of target length"),
    NONCE_NOT_FOUND(HttpStatus.NOT_FOUND, "Nonce with this identifier does not exist"),
    NONCE_ERROR(HttpStatus.CONFLICT, "Nonce metadata is incorrect"),
    INVALID_SIGNATURE(HttpStatus.CONFLICT, "Signature is invalid"),
    PUBLIC_KEY_NOT_READ(HttpStatus.INTERNAL_SERVER_ERROR, "Public key could not be read"),
    TOKEN_NOT_FOUND(HttpStatus.NOT_FOUND, "Token could not be found"),
    EMAIL_PENDING_VERIFICATION(HttpStatus.CONFLICT, "Email is already pending verification"),
    MFA_NONCE_MISSING(HttpStatus.NOT_ACCEPTABLE, "MFA is missing the required Nonce field"),
    MFA_TOTP_ENCRYPTION_FAILED(HttpStatus.CONFLICT, "TOTP encryption failed"),
    MFA_TOTP_DECRYPTION_FAILED(HttpStatus.CONFLICT, "TOTP decryption failed"),
    MFA_TOTP_ALREADY_EXISTS(HttpStatus.CONFLICT, "TOTP for this user is already set"),
    MFA_TOTP_NOT_EXISTS(HttpStatus.CONFLICT, "TOTP for this user does not exist"),
    MFA_TOTP_VERIFICATION_FAILED(HttpStatus.CONFLICT, "Initial TOTP verification failed"),
    MFA_TOTP_LOGIN_MISSING_KEY(HttpStatus.NOT_FOUND, "TOTP login session not found"),
    MFA_TOTP_RECOVERY_CODE_MISMATCH(HttpStatus.CONFLICT, "TOTP recovery code is incorrect");

    private final HttpStatus httpStatus;
    private final String message;

    ErrorEnum(HttpStatus httpStatus, String message) {
        this.httpStatus = httpStatus;
        this.message = message;
    }
}
