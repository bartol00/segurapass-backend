package com.security.passwordmanager.config;

import com.security.passwordmanager.model.authorization.*;
import com.security.passwordmanager.model.deletion.EmailDeletionDao;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
public class ExpiredCleanup {

    @Autowired
    private SessionDao sessionDao;
    @Autowired
    private UserDao userDao;
    @Autowired
    private SrpDao srpDao;
    @Autowired
    private EmailDeletionDao emailDeletionDao;

    @Transactional
    @Scheduled(cron = "0 */2 * * * *")
    public void deleteExpiredEntities() {
        Instant now = Instant.now();
        sessionDao.deleteByExpiryTimeLessThan(now);
        userDao.deleteByVerificationExpiryTimeLessThanAndEmailVerified(now, false);
        srpDao.deleteByExpiryTimeLessThan(now);
        emailDeletionDao.deleteByTokenExpiryLessThan(now);
    }

    @Transactional
    @Scheduled(cron = "0 5 2 * * *")
    public void deleteExpiredByLastLogin() {
        userDao.deleteByLastLoginLessThan(Instant.now().minus(1, ChronoUnit.YEARS));
    }

}
