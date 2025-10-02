package com.security.passwordmanager.mapper;

import com.security.passwordmanager.api.credentials.CredentialsReq;
import com.security.passwordmanager.api.credentials.CredentialsResp;
import com.security.passwordmanager.model.credentials.CredentialsEntity;
import org.mapstruct.Mapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;

import java.util.List;

@Mapper(componentModel = "spring")
public abstract class CredentialMapper {
    public abstract CredentialsEntity toCredentialsEntity(CredentialsReq req);
    public abstract CredentialsResp toCredentialsResp(CredentialsEntity credentials);
    public abstract List<CredentialsResp> toCredentialsRespList(List<CredentialsEntity> list);

    public Page<CredentialsResp> toCredentialsRespPage(Page<CredentialsEntity> page) {
        List<CredentialsResp> content = toCredentialsRespList(page.getContent());
        return new PageImpl<>(content, page.getPageable(), page.getTotalElements());
    }
}
