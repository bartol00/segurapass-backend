package xyz.segurapass.backend.config;

import java.util.UUID;

public record AuthenticatedUser(
        UUID userId,
        UUID deviceId
) {}
