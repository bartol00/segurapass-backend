package com.security.passwordmanager.model.mfa;

import com.security.passwordmanager.model.authorization.UserEntity;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;

@Entity
@Table(name = "totp", schema = "password_manager")
@Getter
@Setter
@ToString
@RequiredArgsConstructor
public class TotpEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, unique = true)
    private Long id;

    @Column(name = "TOTP_TOKEN", nullable = false, unique = true)
    private byte[] totpTokenBytes;

    @Column(name = "TOTP_TOKEN_IV", nullable = false)
    private byte[] totpTokenIv;

    @Column(name = "CREATED_AT", nullable = false)
    private Instant createdAt;

    @OneToOne
    @JoinColumn(name = "USER_ENTITY_ID")
    private UserEntity userEntity;

}
