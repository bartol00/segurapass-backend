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
    @Scheduled(cron = "0 5 2 * * *")
    public void deleteOldAuditLogs() {
        long deletedLogCount = auditLogDao.deleteByTimestampLessThan(
                Instant.now().minus(180, ChronoUnit.DAYS));
        if (deletedLogCount > 0) {
            log.info("Deleted {} old audit logs", deletedLogCount);
        }
    }

    @Transactional
    @Scheduled(cron = "0 7 2 * * *")
    public void deleteStaleUsers() {
        long deletedUserCount = userDao.deleteByLastLoginLessThan(
                Instant.now().minus(366, ChronoUnit.DAYS));
        if(deletedUserCount > 0) {
            log.info("Deleted {} stale users (no login for over a year)", deletedUserCount);
        }
    }

}
