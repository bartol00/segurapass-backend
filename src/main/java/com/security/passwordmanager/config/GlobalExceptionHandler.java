package com.security.passwordmanager.config;

import com.security.passwordmanager.exceptions.*;
import com.security.passwordmanager.exceptions.ErrorEnum;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthorizationException.class)
    public ResponseEntity<String> handleAuthorizationException(AuthorizationException ex) {
        ErrorEnum errorEnum = ex.getErrorEnum();
        return ResponseEntity.status(errorEnum.getHttpStatus()).body(errorEnum.getMessage());
    }

    @ExceptionHandler(AccountDeletionException.class)
    public ResponseEntity<String> handleAccountDeletionException(AccountDeletionException ex) {
        ErrorEnum errorEnum = ex.getErrorEnum();
        return ResponseEntity.status(errorEnum.getHttpStatus()).body(errorEnum.getMessage());
    }

    @ExceptionHandler(CredentialsException.class)
    public ResponseEntity<String> handleCredentialsException(CredentialsException ex) {
        ErrorEnum errorEnum = ex.getErrorEnum();
        return ResponseEntity.status(errorEnum.getHttpStatus()).body(errorEnum.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGenericException(Exception ex) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Something went wrong");
    }
}
