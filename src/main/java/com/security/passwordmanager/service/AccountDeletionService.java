package com.security.passwordmanager.service;

import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.SrpRedisEntity;
import xyz.segurapass.api.deletion.*;
import com.security.passwordmanager.exceptions.AccountDeletionException;
import com.security.passwordmanager.helpers.EmailService;
import com.security.passwordmanager.helpers.SrpFlow;
import com.security.passwordmanager.helpers.TokenGenerator;
import com.security.passwordmanager.helpers.TokenHasher;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.model.deletion.EmailDeletionDao;
import com.security.passwordmanager.model.deletion.EmailDeletionEntity;
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

import static com.security.passwordmanager.exceptions.ErrorEnum.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class AccountDeletionService {

    private final UserDao userDao;
    private final EmailDeletionDao emailDeletionDao;

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
        String redisKey = "segurapass:srp:" + userIdString + ":" + deviceIdString;
        SrpRedisEntity srpRedisEntity = srpFlow.beginFlow(req.getA(), userEntity);
        redisService.save(
                redisKey,
                srpRedisEntity,
                Duration.of(10, ChronoUnit.SECONDS)
        );

        AuthorizedDeletionStartResp resp = new AuthorizedDeletionStartResp();
        resp.setSaltAuth(userEntity.getSaltAuth());
        resp.setB(srpRedisEntity.getB());

        log.info("Start Account Deletion for user {} - Service", userId);

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
        String redisKey = "segurapass:srp:" + userIdString + ":" + deviceIdString;
        if (!redisService.exists(redisKey)) {
            throw new AccountDeletionException(TOKEN_EXPIRED);
        }

        SrpRedisEntity srpRedisEntity = redisService.get(redisKey, SrpRedisEntity.class);
        redisService.delete(redisKey);

        BigInteger M1Server = srpFlow.calculateM1Server(srpRedisEntity);
        BigInteger M1Client = new BigInteger(1, Base64.getDecoder().decode(req.getM1()));

        if (!M1Server.equals(M1Client)) {
            throw new AccountDeletionException(SRP_VERIFICATION_FAILED);
        }

        userDao.deleteByUserId(userId);

        log.info("Complete Account Deletion for user {} - Service", userId);

        return ResponseEntity.ok(null);
    }

    @Transactional
    public void startDeletionEmail(EmailDeletionStartReq req) {
        UserEntity userEntity = userDao.findByEmail(req.getEmail());
        if (userEntity == null) {
            return;
        }
        if (emailDeletionDao.existsByUserEntity(userEntity)) {
            return;
        }

        log.info("Start Email Deletion for user {} - Service", tokenHasher.generateSha256Email(req.getEmail()));

        String deletionToken = tokenGenerator.generateEmailVerifier();

        EmailDeletionEntity emailDeletionEntity = new EmailDeletionEntity();
        emailDeletionEntity.setToken(tokenHasher.generateSha256(deletionToken));
        emailDeletionEntity.setTokenExpiry(Instant.now().plus(15, ChronoUnit.MINUTES));
        emailDeletionEntity.setUserEntity(userEntity);

        emailDeletionDao.save(emailDeletionEntity);

        emailService.sendDeletionEmail(req.getEmail(), deletionToken);
    }

    @Transactional
    public ResponseEntity<String> completeDeletionEmail(String token) {
        EmailDeletionEntity emailDeletionEntity = emailDeletionDao.findByToken(tokenHasher.generateSha256(token));
        if (emailDeletionEntity == null) {
            throw new AccountDeletionException(USER_DELETION_NOT_EXISTS);
        }
        if (emailDeletionEntity.getTokenExpiry().isBefore(Instant.now())) {
            throw new AccountDeletionException(USER_DELETION_EXPIRED);
        }

        log.info("Complete Email Deletion for user {} - Service", tokenHasher.generateSha256Email(emailDeletionEntity.getUserEntity().getEmail()));

        userDao.delete(emailDeletionEntity.getUserEntity());

        return ResponseEntity.ok("Account successfully deleted");
    }

}
