package com.security.passwordmanager.api.error;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.http.HttpStatus;

import java.time.Instant;

@Data
@AllArgsConstructor
public class ApiError {
    private HttpStatus httpStatus;
    private String message;
    private Instant timestamp;

    public ApiError(ApiErrorEnum code) {
        this.httpStatus = code.getHttpStatus();
        this.message = code.getMessage();
        this.timestamp = Instant.now();
    }
}
