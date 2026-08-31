package xyz.segurapass.backend.redis.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SrpRedisEntity {
    private String A;
    private String bpriv;
    private String B;
    private String verifier;
}
