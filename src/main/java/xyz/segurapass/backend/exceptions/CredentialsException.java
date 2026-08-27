package xyz.segurapass.backend.exceptions;

import xyz.segurapass.backend.exceptions.enums.ErrorEnum;
import lombok.Getter;

@Getter
public class CredentialsException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public CredentialsException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
