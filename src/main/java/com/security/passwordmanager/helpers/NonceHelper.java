package com.security.passwordmanager.helpers;

import java.util.function.Function;

public interface NonceHelper {
    String generateNonce(Object writeEntity, Function<String, String> action);
}
