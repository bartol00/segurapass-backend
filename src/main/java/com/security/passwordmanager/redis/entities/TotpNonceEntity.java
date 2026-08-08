package com.security.passwordmanager.redis.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import xyz.segurapass.api.mfa.MfaType;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TotpNonceEntity {
    private UUID userId;
    private UUID deviceId;
    private MfaType mfaType;
}
