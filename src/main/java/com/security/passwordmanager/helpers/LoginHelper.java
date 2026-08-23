package com.security.passwordmanager.helpers;

import com.security.passwordmanager.model.authorization.UserEntity;
import xyz.segurapass.api.authorization.LoginCompleteReq;
import xyz.segurapass.api.authorization.LoginCompleteResp;

import java.math.BigInteger;
import java.util.UUID;

public interface LoginHelper {

    LoginCompleteResp generateLoginCompleteResp(UUID userId, UUID deviceId);
    LoginCompleteResp generateMfaLoginResp(
            UserEntity userEntity,
            LoginCompleteReq req,
            BigInteger M2Server
    );

}
