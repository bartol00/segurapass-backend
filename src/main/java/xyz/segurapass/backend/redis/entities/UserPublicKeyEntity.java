package xyz.segurapass.backend.redis.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserPublicKeyEntity {
    private byte[] publicKeyBytes;
}
