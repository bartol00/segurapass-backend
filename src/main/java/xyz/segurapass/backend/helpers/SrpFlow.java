package xyz.segurapass.backend.helpers;

import xyz.segurapass.backend.model.authorization.UserEntity;
import xyz.segurapass.backend.redis.entities.SrpRedisEntity;

import java.math.BigInteger;

public interface SrpFlow {
    SrpRedisEntity beginFlow(String A, UserEntity userEntity);
    BigInteger calculateM1Server(SrpRedisEntity srpRedisEntity);
    BigInteger calculateM2Server(SrpRedisEntity srpRedisEntity, BigInteger M1Client);
}
