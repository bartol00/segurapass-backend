package xyz.segurapass.backend.exceptions;

import xyz.segurapass.backend.exceptions.enums.ErrorEnum;
import lombok.Getter;

@Getter
public class AuthorizationException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public AuthorizationException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
