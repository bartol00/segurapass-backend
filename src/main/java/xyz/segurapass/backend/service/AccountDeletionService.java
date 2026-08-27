package xyz.segurapass.backend.service;

import xyz.segurapass.backend.config.EmailClient;
import xyz.segurapass.backend.redis.RedisKeys;
import xyz.segurapass.backend.redis.RedisService;
import xyz.segurapass.backend.redis.entities.EmailDeletionRedisEntity;
import xyz.segurapass.backend.redis.entities.SrpRedisEntity;
import xyz.segurapass.api.deletion.*;
import xyz.segurapass.backend.exceptions.AccountDeletionException;
import xyz.segurapass.backend.helpers.EmailService;
import xyz.segurapass.backend.helpers.SrpFlow;
import xyz.segurapass.backend.helpers.TokenGenerator;
import xyz.segurapass.backend.helpers.TokenHasher;
import xyz.segurapass.backend.model.authorization.UserDao;
import xyz.segurapass.backend.model.authorization.UserEntity;
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

import static xyz.segurapass.backend.exceptions.enums.ErrorEnum.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class AccountDeletionService {

    private final UserDao userDao;

    private final RedisService redisService;
    private final EmailService emailService;
    private final EmailClient emailClient;
    private final TokenGenerator tokenGenerator;
    private final TokenHasher tokenHasher;
    private final SrpFlow srpFlow;

    @Transactional
    public ResponseEntity<AuthorizedDeletionStartResp> startAuthorizedDeletion(
            UUID userId,
            AuthorizedDeletionStartReq req
    ) {
        UserEntity userEntity = userDao.findByUserId(userId);
        if (userEntity == null) {
            log.warn("User does not exist - Authorized Deletion Start");
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

        log.info("Account Deletion Start");

        return ResponseEntity.ok(resp);
    }

    @Transactional
    public ResponseEntity<Void> completeAuthorizedDeletion(
            UUID userId,
            AuthorizedDeletionCompleteReq req
    ) {
        UserEntity userEntity = userDao.findByUserId(userId);
        if (userEntity == null) {
            log.warn("User does not exist - Authorized Deletion Complete");
            throw new AccountDeletionException(USER_NOT_EXISTS);
        }

        String userIdString = userEntity.getUserId().toString();
        String deviceIdString = req.getDeviceId().toString();
        String redisKey = RedisKeys.accountDeletion(userIdString, deviceIdString);
        if (!redisService.exists(redisKey)) {
            log.warn("Token could not be found {} - Authorized Deletion Complete", redisKey);
            throw new AccountDeletionException(TOKEN_NOT_FOUND);
        }

        SrpRedisEntity srpRedisEntity = redisService.get(redisKey, SrpRedisEntity.class);
        redisService.delete(redisKey);

        BigInteger M1Server = srpFlow.calculateM1Server(srpRedisEntity);
        BigInteger M1Client = new BigInteger(1, Base64.getDecoder().decode(req.getM1()));

        if (!M1Server.equals(M1Client)) {
            log.warn("M1 could not be verified - Account Deletion Complete");
            throw new AccountDeletionException(PASSWORD_INCORRECT);
        }

        userDao.deleteByUserId(userId);

        log.info("Account Deletion Complete");

        return ResponseEntity.ok(null);
    }

    @Transactional
    public void startDeletionEmail(EmailDeletionStartReq req) {
        if (!emailClient.isActive()) {
            throw new AccountDeletionException(EMAIL_VERIFICATION_OFF);
        }

        String emailHash = tokenHasher.generateSha256Email(req.getEmail());

        UserEntity userEntity = userDao.findByEmail(req.getEmail());
        if (userEntity == null) {
            log.warn("Email does not exist {} - Email Deletion Start", emailHash);
            return;
        }

        String redisEmailKey = RedisKeys.emailDeletionEmail(emailHash);
        if (redisService.exists(redisEmailKey)) {
            log.warn("Token already exists {} - Email Deletion Start", redisEmailKey);
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

        log.info("Email Deletion Start for user {}", userEntity.getUserId());
    }

    @Transactional
    public ResponseEntity<String> completeDeletionEmail(String token) {
        if (!emailClient.isActive()) {
            throw new AccountDeletionException(EMAIL_VERIFICATION_OFF);
        }

        String tokenHash = tokenHasher.generateSha256(token);
        String redisKey = RedisKeys.emailDeletion(tokenHash);
        if (!redisService.exists(redisKey)) {
            log.warn("Token could not be found {} - Email Deletion Complete", redisKey);
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
        userDao.delete(userEntity);

        log.info("Email Deletion Complete for user {}", userId);

        return ResponseEntity.ok("Account successfully deleted");
    }

}
