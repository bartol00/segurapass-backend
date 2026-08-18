package com.security.passwordmanager.service;

import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.EmailDeletionRedisEntity;
import com.security.passwordmanager.redis.entities.SrpRedisEntity;
import xyz.segurapass.api.deletion.*;
import com.security.passwordmanager.exceptions.AccountDeletionException;
import com.security.passwordmanager.helpers.EmailService;
import com.security.passwordmanager.helpers.SrpFlow;
import com.security.passwordmanager.helpers.TokenGenerator;
import com.security.passwordmanager.helpers.TokenHasher;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

import static com.security.passwordmanager.exceptions.enums.ErrorEnum.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class AccountDeletionService {

    private final UserDao userDao;

    private final RedisService redisService;
    private final EmailService emailService;
    private final TokenGenerator tokenGenerator;
    private final TokenHasher tokenHasher;
    private final SrpFlow srpFlow;

    @Transactional
    public ResponseEntity<AuthorizedDeletionStartResp> startAuthorizedDeletion(UUID userId, AuthorizedDeletionStartReq req) {
        UserEntity userEntity = userDao.findByUserId(userId);
        if (userEntity == null) {
            throw new AccountDeletionException(USER_NOT_EXISTS);
        }

        String userIdString = userEntity.getUserId().toString();
        String deviceIdString = req.getDeviceId().toString();
        String redisKey = RedisKeys.accountDeletion(userIdString, deviceIdString);
        SrpRedisEntity srpRedisEntity = srpFlow.beginFlow(req.getA(), userEntity);
        redisService.save(
                redisKey,
                srpRedisEntity,
                Duration.of(10, ChronoUnit.SECONDS)
        );

        AuthorizedDeletionStartResp resp = new AuthorizedDeletionStartResp();
        resp.setSaltAuth(userEntity.getSaltAuthBytes());
        resp.setB(srpRedisEntity.getB());

        log.info("Start Account Deletion for user: {} - Service", userId);

        return ResponseEntity.ok(resp);
    }

    @Transactional
    public ResponseEntity<Void> completeAuthorizedDeletion(UUID userId, AuthorizedDeletionCompleteReq req) {
        UserEntity userEntity = userDao.findByUserId(userId);
        if (userEntity == null) {
            throw new AccountDeletionException(USER_NOT_EXISTS);
        }

        String userIdString = userEntity.getUserId().toString();
        String deviceIdString = req.getDeviceId().toString();
        String redisKey = RedisKeys.accountDeletion(userIdString, deviceIdString);
        if (!redisService.exists(redisKey)) {
            throw new AccountDeletionException(TOKEN_NOT_FOUND);
        }

        SrpRedisEntity srpRedisEntity = redisService.get(redisKey, SrpRedisEntity.class);
        redisService.delete(redisKey);

        BigInteger M1Server = srpFlow.calculateM1Server(srpRedisEntity);
        BigInteger M1Client = new BigInteger(1, Base64.getDecoder().decode(req.getM1()));

        if (!M1Server.equals(M1Client)) {
            throw new AccountDeletionException(SRP_VERIFICATION_FAILED);
        }

        userDao.deleteByUserId(userId);

        log.info("Complete Account Deletion for user: {} - Service", userId);

        return ResponseEntity.ok(null);
    }

    @Transactional
    public void startDeletionEmail(EmailDeletionStartReq req) {
        UserEntity userEntity = userDao.findByEmail(req.getEmail());
        if (userEntity == null) {
            return;
        }
        String emailHash = tokenHasher.generateSha256Email(userEntity.getEmail());
        String redisEmailKey = RedisKeys.emailDeletionEmail(emailHash);
        if (redisService.exists(redisEmailKey)) {
            return;
        }

        String deletionToken = tokenGenerator.generateRandomToken(32);
        String tokenHash = tokenHasher.generateSha256(deletionToken);
        String redisKey = RedisKeys.emailDeletion(tokenHash);
        EmailDeletionRedisEntity emailDeletionRedisEntity = new EmailDeletionRedisEntity(
                userEntity.getUserId(),
                emailHash
        );
        Instant in15Minutes = Instant.now().plus(15, ChronoUnit.MINUTES);
        redisService.save(
                redisKey,
                emailDeletionRedisEntity,
                Duration.between(Instant.now(), in15Minutes)
        );
        redisService.save(
                redisEmailKey,
                null,
                Duration.between(Instant.now(), in15Minutes)
        );

        emailService.sendDeletionEmail(userEntity.getEmail(), deletionToken);

        log.info("Start Email Deletion for user (email hash): {} - Service", emailHash);
    }

    @Transactional
    public ResponseEntity<String> completeDeletionEmail(String token) {
        String tokenHash = tokenHasher.generateSha256(token);
        String redisKey = RedisKeys.emailDeletion(tokenHash);
        if (!redisService.exists(redisKey)) {
            throw new AccountDeletionException(TOKEN_NOT_FOUND);
        }

        EmailDeletionRedisEntity emailDeletionRedisEntity = redisService.get(
                redisKey,
                EmailDeletionRedisEntity.class
        );
        UUID userId = emailDeletionRedisEntity.getUserId();

        redisService.delete(redisKey);

        String emailHashRedisKey = RedisKeys.emailDeletionEmail(emailDeletionRedisEntity.getEmailHash());
        redisService.delete(emailHashRedisKey);

        UserEntity userEntity = userDao.findByUserId(userId);
        String emailHash = tokenHasher.generateSha256Email(userEntity.getEmail());
        userDao.delete(userEntity);

        log.info("Complete Email Deletion for user (email hash): {} - Service", emailHash);

        return ResponseEntity.ok("Account successfully deleted");
    }

}
