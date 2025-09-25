package com.security.passwordmanager.mapper;

import com.security.passwordmanager.api.authorization.RegistrationReq;
import com.security.passwordmanager.model.UserEntity;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public abstract class UserMapper {
    public abstract UserEntity toUserEntity(RegistrationReq req);
}
