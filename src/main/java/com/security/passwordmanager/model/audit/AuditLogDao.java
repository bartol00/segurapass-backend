package com.security.passwordmanager.model.audit;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface AuditLogDao extends JpaRepository<AuditLogEntity, Long> {
    long deleteByTimestampLessThan(Instant timestamp);
}
