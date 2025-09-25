package com.security.passwordmanager.model;

import org.springframework.data.jpa.repository.JpaRepository;

public interface NonceDao extends JpaRepository<NonceEntity, Long> {
}
