package xyz.segurapass.backend.redis.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import xyz.segurapass.api.credentials.CredentialsOperation;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CredentialsWriteEntity {
    private UUID userId;
    private UUID deviceId;
    private CredentialsOperation operation;
    private UUID credentialsId;
}
