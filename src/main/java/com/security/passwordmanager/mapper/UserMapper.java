package com.security.passwordmanager.mapper;

import xyz.segurapass.api.authorization.RegistrationReq;
import com.security.passwordmanager.model.authorization.UserEntity;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public abstract class UserMapper {
    public abstract UserEntity toUserEntity(RegistrationReq req);
}
