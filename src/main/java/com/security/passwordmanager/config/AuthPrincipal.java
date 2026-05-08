package com.security.passwordmanager.config;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.UUID;

@Getter
@AllArgsConstructor
public class AuthPrincipal {
    private final UUID userId;
}
