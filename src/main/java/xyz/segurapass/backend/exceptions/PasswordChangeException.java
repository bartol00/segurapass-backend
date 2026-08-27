package xyz.segurapass.backend.exceptions;

import xyz.segurapass.backend.exceptions.enums.ErrorEnum;
import lombok.Getter;

@Getter
public class PasswordChangeException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public PasswordChangeException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
