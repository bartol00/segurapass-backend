package xyz.segurapass.backend.exceptions;

import xyz.segurapass.backend.exceptions.enums.ErrorEnum;
import lombok.Getter;

@Getter
public class KeysException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public KeysException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
