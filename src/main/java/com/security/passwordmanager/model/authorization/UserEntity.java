package com.security.passwordmanager.model.authorization;

import com.security.passwordmanager.model.credentials.CredentialsEntity;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.Length;
import org.hibernate.proxy.HibernateProxy;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "users", schema = "password_manager")
@Getter
@Setter
@ToString
@RequiredArgsConstructor
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, unique = true)
    private Long id;

    @Column(name = "USER_ID", nullable = false, unique = true)
    private UUID userId;

    @Column(name = "EMAIL", nullable = false, unique = true)
    private String email;

    @Column(name = "SALT_AUTH", nullable = false, unique = true)
    private String saltAuth;

    @Column(name = "VERIFIER", nullable = false, unique = true, length = Length.LONG32)
    private String verifier;

    @Column(name = "VAULT_KEY", nullable = false, unique = true, length = Length.LONG32)
    private String vaultKey;

    @Column(name = "IV_VAULT_KEY", nullable = false, unique = true)
    private String ivVaultKey;

    @Column(name = "SALT_KEY", nullable = false, unique = true)
    private String saltKey;

    @Column(name = "SALT_HKDF", nullable = false, unique = true)
    private String saltHkdf;

    @Column(name = "PRIVATE_SIGNING_KEY", nullable = false, unique = true, length = Length.LONG32)
    private String privateSigningKey;

    @Column(name = "PUBLIC_SIGNING_KEY", nullable = false, unique = true, length = Length.LONG32)
    private String publicSigningKey;

    @Column(name = "IV_PRIVATE_SIGNING_KEY", nullable = false, unique = true)
    private String ivPrivateSigningKey;

    @Column(name = "CREATION_TIME")
    private Instant creationTime;

    @Column(name = "LAST_LOGIN")
    private Instant lastLogin;

    @OneToMany(mappedBy = "userEntity", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<CredentialsEntity> credentialsEntities;

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        UserEntity that = (UserEntity) o;
        return getId() != null && Objects.equals(getId(), that.getId());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
