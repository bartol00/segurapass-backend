package com.security.passwordmanager.config;

import com.security.passwordmanager.model.authorization.*;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Component
public class ExpiredCleanup {

    @Autowired
    private SessionDao sessionDao;
    @Autowired
    private UserDao userDao;
    @Autowired
    private SrpDao srpDao;

    @Transactional
    @Scheduled(cron = "0 */2 * * * *")
    public void deleteExpiredEntities() {
        Instant now = Instant.now();
        sessionDao.deleteByExpiryTimeLessThan(now);
        userDao.deleteByVerificationExpiryTimeLessThanAndEmailVerified(now, false);
        srpDao.deleteByExpiryTimeLessThan(now);
        // System.out.println("Current time: " + now.toString());
    }

}
