package com.security.passwordmanager.service;

import com.security.passwordmanager.api.deletion.AuthorizedDeletionCompleteReq;
import com.security.passwordmanager.api.deletion.AuthorizedDeletionStartReq;
import com.security.passwordmanager.api.deletion.AuthorizedDeletionStartResp;
import com.security.passwordmanager.api.deletion.EmailDeletionStartReq;
import com.security.passwordmanager.api.error.ApiError;
import com.security.passwordmanager.api.error.ApiErrorEnum;
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
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class AccountDeletionService {

    private final UserDao userDao;
    private final EmailDeletionDao emailDeletionDao;
    private final SrpDao srpDao;

    private final EmailService emailService;
    private final TokenGenerator tokenGenerator;
    private final TokenHasher tokenHasher;
    private final SrpFlow srpFlow;

    @Transactional
    public ResponseEntity<?> startAuthorizedDeletion(String email, AuthorizedDeletionStartReq req) {
        UserEntity userEntity = userDao.findByEmail(email);
        if (userEntity == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        SrpEntity srpEntity = srpFlow.beginFlow(req.getA(), req.getDeviceId(), userEntity);

        SrpEntity existing = srpDao.findByUserEntity_EmailAndDeviceId(email, req.getDeviceId());
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
    public ResponseEntity<?> completeAuthorizedDeletion(String email, AuthorizedDeletionCompleteReq req) {
        SrpEntity srpEntity = srpDao.findByUserEntity_EmailAndDeviceId(email, req.getDeviceId());
        if (srpEntity == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.SRP_SESSION_NOT_FOUND);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        srpDao.delete(srpEntity);

        if (srpEntity.getExpiryTime().isBefore(Instant.now())) {
            ApiError apiError = new ApiError(ApiErrorEnum.SRP_SESSION_EXPIRED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        BigInteger M1Server = srpFlow.calculateM1Server(srpEntity);
        BigInteger M1Client = new BigInteger(1, Base64.getDecoder().decode(req.getM1()));

        if (!M1Server.equals(M1Client)) {
            ApiError apiError = new ApiError(ApiErrorEnum.SRP_VERIFICATION_FAILED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        userDao.deleteByEmail(email);

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

        String deletionToken = tokenGenerator.generateEmailVerifier();

        EmailDeletionEntity emailDeletionEntity = new EmailDeletionEntity();
        emailDeletionEntity.setToken(tokenHasher.generateSha256(deletionToken));
        emailDeletionEntity.setTokenExpiry(Instant.now().plus(15, ChronoUnit.MINUTES));
        emailDeletionEntity.setUserEntity(userEntity);

        emailDeletionDao.save(emailDeletionEntity);

        emailService.sendDeletionEmail(req.getEmail(), deletionToken);
    }

    @Transactional
    public ResponseEntity<?> completeDeletionEmail(String token) {
        EmailDeletionEntity emailDeletionEntity = emailDeletionDao.findByToken(tokenHasher.generateSha256(token));
        if (emailDeletionEntity == null) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_DELETION_NOT_EXISTS);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }
        if (emailDeletionEntity.getTokenExpiry().isBefore(Instant.now())) {
            ApiError apiError = new ApiError(ApiErrorEnum.USER_DELETION_EXPIRED);
            return ResponseEntity.status(apiError.getHttpStatus()).body(apiError);
        }

        userDao.delete(emailDeletionEntity.getUserEntity());

        return ResponseEntity.ok("Account successfully deleted remotely");
    }

}
