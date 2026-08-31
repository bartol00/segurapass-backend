package xyz.segurapass.backend.exceptions;

import xyz.segurapass.backend.exceptions.enums.ErrorEnum;
import lombok.Getter;

@Getter
public class MfaException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public MfaException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
