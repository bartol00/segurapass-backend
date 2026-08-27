package xyz.segurapass.backend.redis.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TotpLoginEntity {
    private UUID userId;
    private UUID deviceId;
    private byte[] totpSecretBytes;
    private byte[] totpSecretIv;
}
