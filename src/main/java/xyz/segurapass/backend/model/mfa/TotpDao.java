package xyz.segurapass.backend.model.mfa;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface TotpDao extends JpaRepository<TotpEntity, Long> {
    TotpEntity findByUserEntity_UserId(UUID userId);
    void deleteByUserEntity_UserId(UUID userId);
}
