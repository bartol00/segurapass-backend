package com.security.passwordmanager.helpers;

import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.redis.entities.SrpRedisEntity;

import java.math.BigInteger;

public interface SrpFlow {
    SrpRedisEntity beginFlow(String A, UserEntity userEntity);
    BigInteger calculateM1Server(SrpRedisEntity srpRedisEntity);
    BigInteger calculateM2Server(SrpRedisEntity srpRedisEntity, BigInteger M1Client);
}
