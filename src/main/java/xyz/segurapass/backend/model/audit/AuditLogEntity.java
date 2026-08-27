package xyz.segurapass.backend.model.audit;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "audit_log", schema = "password_manager")
@Getter
@Setter
@ToString
@RequiredArgsConstructor
public class AuditLogEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false)
    private Long id;

    @Column(name = "USER_ID", nullable = false)
    private UUID userId;

    @Column(name = "TIMESTAMP", nullable = false)
    private Instant timestamp;

    @Enumerated(EnumType.STRING)
    @Column(name = "AUDIT_ACTION", nullable = false)
    private AuditAction action;

    @Column(name = "IP_ADDRESS", nullable = false)
    private String ipAddress;

    @Column(name = "SUCCESS", nullable = false)
    private boolean success;

    @Column(name = "COMMENT")
    private String comment;

}
