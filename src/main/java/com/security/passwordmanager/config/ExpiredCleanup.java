package com.security.passwordmanager.config;

import com.security.passwordmanager.model.audit.AuditLogDao;
import com.security.passwordmanager.model.authorization.*;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
@Slf4j
public class ExpiredCleanup {

    @Autowired
    private UserDao userDao;
    @Autowired
    private AuditLogDao auditLogDao;

    @Transactional
    @Scheduled(cron = "0 5 2,14 * * *")
    public void deleteOldAuditLogs() {
        auditLogDao.deleteByTimestampLessThan(Instant.now().minus(180, ChronoUnit.DAYS));
        log.info("Deleted old audit logs");
        userDao.deleteByLastLoginLessThan(Instant.now().minus(366, ChronoUnit.DAYS));
        log.info("Deleted expired entities (no login for over a year)");
    }

}
