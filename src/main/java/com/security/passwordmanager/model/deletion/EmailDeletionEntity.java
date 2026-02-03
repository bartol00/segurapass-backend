package com.security.passwordmanager.model.deletion;

import com.security.passwordmanager.model.authorization.UserEntity;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;

@Entity
@Table(name = "email_deletion", schema = "password_manager")
@Getter
@Setter
@ToString
@RequiredArgsConstructor
public class EmailDeletionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, unique = true)
    private Long id;

    @Column(name = "TOKEN", nullable = false, unique = true)
    private String token;

    @Column(name = "TOKEN_EXPIRY", nullable = false)
    private Instant tokenExpiry;

    @ManyToOne
    @JoinColumn(name = "USER_ENTITY_ID")
    private UserEntity userEntity;

}
