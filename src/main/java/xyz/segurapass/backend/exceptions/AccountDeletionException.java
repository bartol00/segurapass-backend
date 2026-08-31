package xyz.segurapass.backend.exceptions;

import xyz.segurapass.backend.exceptions.enums.ErrorEnum;
import lombok.Getter;

@Getter
public class AccountDeletionException extends RuntimeException {
    private final ErrorEnum errorEnum;

    public AccountDeletionException(ErrorEnum errorEnum) {
        this.errorEnum = errorEnum;
    }
}
