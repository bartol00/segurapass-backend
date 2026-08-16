package com.security.passwordmanager.model.credentials;

import com.security.passwordmanager.model.authorization.UserEntity;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "credentials", schema = "password_manager")
@Getter
@Setter
@ToString
@RequiredArgsConstructor
public class CredentialsEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, unique = true)
    private Long id;

    @Column(name = "CREDENTIALS_ID", nullable = false, unique = true)
    private UUID credentialsId;

    @Column(name = "WEBSITE_BYTES", nullable = false)
    private byte[] websiteBytes;

    @Column(name = "IV_WEBSITE_BYTES", nullable = false)
    private byte[] ivWebsiteBytes;

    @Column(name = "USERNAME_BYTES", nullable = false)
    private byte[] usernameBytes;

    @Column(name = "IV_USERNAME_BYTES", nullable = false)
    private byte[] ivUsernameBytes;

    @Column(name = "PASSWORD_BYTES", nullable = false)
    private byte[] passwordBytes;

    @Column(name = "IV_PASSWORD_BYTES", nullable = false)
    private byte[] ivPasswordBytes;

    @Column(name = "CREATED_AT", nullable = false)
    private Instant createdAt;

    @Column(name = "LAST_UPDATED", nullable = false)
    private Instant lastUpdated;

    @ManyToOne
    @JoinColumn(name = "USER_ENTITY_ID")
    private UserEntity userEntity;

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        CredentialsEntity that = (CredentialsEntity) o;
        return getId() != null && Objects.equals(getId(), that.getId());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
