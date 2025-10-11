package com.security.passwordmanager.config;

import com.security.passwordmanager.model.authorization.SessionDao;
import com.security.passwordmanager.model.authorization.SessionEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Component
public class ExpiredCleanup {

    @Autowired
    private SessionDao sessionDao;

    @Scheduled(cron = "0 */2 * * * *")
    public void deleteExpiredEntities() {
        Instant now = Instant.now();
        List<SessionEntity> expiredSessions = sessionDao.findByExpiryTimeLessThanEqual(now);
        sessionDao.deleteAll(expiredSessions);
        // System.out.println("Current time: " + now.toString());
    }

}
