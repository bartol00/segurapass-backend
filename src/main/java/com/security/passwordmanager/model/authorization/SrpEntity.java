package com.security.passwordmanager.model.authorization;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.Length;
import org.hibernate.proxy.HibernateProxy;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "srp_session", schema = "password_manager")
@Getter
@Setter
@ToString
@RequiredArgsConstructor
public class SrpEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, unique = true)
    private Long id;

    @Column(name = "A", length = Length.LONG32)
    private String A;

    @Column(name = "BPRIV", length = Length.LONG32)
    private String bpriv;

    @Column(name = "B", length = Length.LONG32)
    private String B;

    @Column(name = "VERIFIER", length = Length.LONG32)
    private String verifier;

    @Column(name = "DEVICE_ID", nullable = false)
    private UUID deviceId;

    @ManyToOne
    @JoinColumn(name = "USER_ENTITY_ID")
    private UserEntity userEntity;

    @Column(name = "EXPIRY_TIME", nullable = false)
    private Instant expiryTime;

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        SrpEntity srpEntity = (SrpEntity) o;
        return getId() != null && Objects.equals(getId(), srpEntity.getId());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}