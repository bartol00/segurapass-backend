package com.security.passwordmanager.config;

import com.security.passwordmanager.model.authorization.SessionDao;
import com.security.passwordmanager.model.authorization.SessionEntity;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
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

    @Scheduled(cron = "0 */2 * * * *")
    public void deleteExpiredEntities() {
        Instant now = Instant.now();
        List<SessionEntity> expiredSessions = sessionDao.findByExpiryTimeLessThanEqual(now);
        sessionDao.deleteAll(expiredSessions);
        List<UserEntity> unverifiedUsers = userDao.findByVerificationExpiryTimeLessThanAndEmailVerified(now, false);
        userDao.deleteAll(unverifiedUsers);
        // System.out.println("Current time: " + now.toString());
    }

}
