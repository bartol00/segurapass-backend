package xyz.segurapass.backend.redis.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class EmailDeletionRedisEntity {
    private UUID userId;
    private String emailHash;
}
