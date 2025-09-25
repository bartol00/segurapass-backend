package com.security.passwordmanager.model;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionDao extends JpaRepository<SessionEntity, Long> {
}
