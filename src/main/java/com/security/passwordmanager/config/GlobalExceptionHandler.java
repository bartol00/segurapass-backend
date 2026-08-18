package com.security.passwordmanager.config;

import com.security.passwordmanager.exceptions.*;
import com.security.passwordmanager.exceptions.enums.ErrorEnum;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(AccountDeletionException.class)
    public ResponseEntity<String> handleAccountDeletionException(AccountDeletionException ex) {
        ErrorEnum errorEnum = ex.getErrorEnum();
        log.warn("Account Deletion Exception: {}", errorEnum.getMessage());
        return ResponseEntity.status(errorEnum.getHttpStatus()).body(errorEnum.getMessage());
    }

    @ExceptionHandler(AuthorizationException.class)
    public ResponseEntity<String> handleAuthorizationException(AuthorizationException ex) {
        ErrorEnum errorEnum = ex.getErrorEnum();
        log.warn("Authorization Exception: {}", errorEnum.getMessage());
        return ResponseEntity.status(errorEnum.getHttpStatus()).body(errorEnum.getMessage());
    }

    @ExceptionHandler(CredentialsException.class)
    public ResponseEntity<String> handleCredentialsException(CredentialsException ex) {
        ErrorEnum errorEnum = ex.getErrorEnum();
        log.warn("Credentials Exception: {}", errorEnum.getMessage());
        return ResponseEntity.status(errorEnum.getHttpStatus()).body(errorEnum.getMessage());
    }

    @ExceptionHandler(KeysException.class)
    public ResponseEntity<String> handleKeysException(KeysException ex) {
        ErrorEnum errorEnum = ex.getErrorEnum();
        log.warn("Keys Exception: {}", errorEnum.getMessage());
        return ResponseEntity.status(errorEnum.getHttpStatus()).body(errorEnum.getMessage());
    }

    @ExceptionHandler(MfaException.class)
    public ResponseEntity<String> handleMfaException(MfaException ex) {
        ErrorEnum errorEnum = ex.getErrorEnum();
        log.warn("MFA Exception: {}", errorEnum.getMessage());
        return ResponseEntity.status(errorEnum.getHttpStatus()).body(errorEnum.getMessage());
    }

    @ExceptionHandler(PasswordChangeException.class)
    public ResponseEntity<String> handlePasswordChangeException(PasswordChangeException ex) {
        ErrorEnum errorEnum = ex.getErrorEnum();
        log.warn("Password Change Exception: {}", errorEnum.getMessage());
        return ResponseEntity.status(errorEnum.getHttpStatus()).body(errorEnum.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGenericException(Exception ex) {
        log.error("Exception: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Something went wrong");
    }
}
