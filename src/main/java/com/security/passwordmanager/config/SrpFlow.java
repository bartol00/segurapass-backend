package com.security.passwordmanager.config;

import com.security.passwordmanager.model.authorization.SrpEntity;
import com.security.passwordmanager.model.authorization.UserEntity;

import java.math.BigInteger;
import java.util.UUID;

public interface SrpFlow {
    SrpEntity beginFlow(String A, UUID deviceId, UserEntity userEntity);
    BigInteger calculateM1Server(SrpEntity srpEntity);
    BigInteger calculateM2Server(SrpEntity srpEntity, BigInteger M1Client);
}
