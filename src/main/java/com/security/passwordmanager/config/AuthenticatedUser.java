package com.security.passwordmanager.config;

import java.util.UUID;

public record AuthenticatedUser(
        UUID userId,
        UUID deviceId
) {}
