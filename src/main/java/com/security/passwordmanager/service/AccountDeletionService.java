package com.security.passwordmanager.service;

import xyz.segurapass.api.deletion.*;
import com.security.passwordmanager.exceptions.AccountDeletionException;
import com.security.passwordmanager.helpers.EmailService;
import com.security.passwordmanager.helpers.SrpFlow;
import com.security.passwordmanager.helpers.TokenGenerator;
import com.security.passwordmanager.helpers.TokenHasher;
import com.security.passwordmanager.model.authorization.SrpDao;
import com.security.passwordmanager.model.authorization.SrpEntity;
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
    private final SrpDao srpDao;

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

        log.info("Start Account Deletion for user {} - Service", userId);

        SrpEntity srpEntity = srpFlow.beginFlow(req.getA(), req.getDeviceId(), userEntity);

        SrpEntity existing = srpDao.findByUserEntity_UserIdAndDeviceId(userId, req.getDeviceId());
        if (existing != null) {
            srpDao.delete(existing);
        }
        srpDao.save(srpEntity);

        AuthorizedDeletionStartResp resp = new AuthorizedDeletionStartResp();
        resp.setSaltAuth(userEntity.getSaltAuth());
        resp.setB(srpEntity.getB());

        return ResponseEntity.ok(resp);
    }

    @Transactional
    public ResponseEntity<Void> completeAuthorizedDeletion(UUID userId, AuthorizedDeletionCompleteReq req) {
        SrpEntity srpEntity = srpDao.findByUserEntity_UserIdAndDeviceId(userId, req.getDeviceId());
        if (srpEntity == null) {
            throw new AccountDeletionException(SRP_SESSION_NOT_FOUND);
        }

        srpDao.delete(srpEntity);

        if (srpEntity.getExpiryTime().isBefore(Instant.now())) {
            throw new AccountDeletionException(SRP_SESSION_EXPIRED);
        }

        log.info("Complete Account Deletion for user {} - Service", userId);

        BigInteger M1Server = srpFlow.calculateM1Server(srpEntity);
        BigInteger M1Client = new BigInteger(1, Base64.getDecoder().decode(req.getM1()));

        if (!M1Server.equals(M1Client)) {
            throw new AccountDeletionException(SRP_VERIFICATION_FAILED);
        }

        userDao.deleteByUserId(userId);

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
