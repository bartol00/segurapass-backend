package com.security.passwordmanager;

import com.security.passwordmanager.exceptions.PasswordChangeException;
import com.security.passwordmanager.helpers.SrpFlow;
import com.security.passwordmanager.model.audit.AuditLogDao;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.model.authorization.UserEntity;
import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.SrpRedisEntity;
import com.security.passwordmanager.service.PasswordChangeService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import xyz.segurapass.api.password.*;

import java.math.BigInteger;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

import static com.security.passwordmanager.exceptions.enums.ErrorEnum.*;
import static org.junit.jupiter.api.Assertions.*;
import static com.security.passwordmanager.shared.HelperMethods.*;

@SpringBootTest
public class PasswordChangeIT extends AbstractTestInitializer {

    @Autowired
    private PasswordChangeService passwordChangeService;
    @Autowired
    private UserDao userDao;
    @Autowired
    private AuditLogDao auditLogDao;
    @Autowired
    private RedisService redisService;
    @Autowired
    private SrpFlow srpFlow;

    @BeforeEach
    void setup() {
        UserEntity userEntity = generateUserEntity();
        userDao.save(userEntity);
        MDC.put("clientIp", "127.0.0.1");
    }

    @AfterEach
    void cleanup() {
        userDao.deleteAll();
        auditLogDao.deleteAll();
        redisService.clearAll();
        MDC.clear();
    }

    @Test
    void shouldFailUserIsNullStartPasswordChange() {
        // given
        UUID userId = UUID.randomUUID();
        UUID deviceId = UUID.randomUUID();
        PasswordChangeStartReq req = generatePasswordChangeStartReq(deviceId);

        // when
        PasswordChangeException ex = assertThrows(
                PasswordChangeException.class,
                () -> passwordChangeService.startPasswordChange(userId, req)
        );

        // then
        assertEquals(USER_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedStartPasswordChange() {
        // given
        UserEntity userEntity = userDao.findByUserId(userId);
        UUID deviceId = UUID.randomUUID();
        String redisKey = RedisKeys.passwordChange(userId.toString(), deviceId.toString());
        PasswordChangeStartReq req = generatePasswordChangeStartReq(deviceId);
        assertFalse(redisService.exists(redisKey));

        // when
        ResponseEntity<PasswordChangeStartResp> response = passwordChangeService.startPasswordChange(userId, req);

        // then
        assertTrue(redisService.exists(redisKey));
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertArrayEquals(userEntity.getSaltAuthBytes(), response.getBody().getSaltAuth());
    }

    @Test
    void shouldFailUserIsNullCompletePasswordChange() {
        // given
        UUID userId = UUID.randomUUID();
        UUID deviceId = UUID.randomUUID();
        PasswordChangeCompleteReq req = generatePasswordChangeCompleteReq(deviceId, "M1");

        // when
        PasswordChangeException ex = assertThrows(
                PasswordChangeException.class,
                () -> passwordChangeService.completePasswordChange(userId, req)
        );

        // then
        assertEquals(USER_NOT_EXISTS.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(USER_NOT_EXISTS.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailTokenNotFoundCompletePasswordChange() {
        // given
        UUID deviceId = UUID.randomUUID();
        PasswordChangeCompleteReq req = generatePasswordChangeCompleteReq(deviceId, "M1");

        // when
        PasswordChangeException ex = assertThrows(
                PasswordChangeException.class,
                () -> passwordChangeService.completePasswordChange(userId, req)
        );

        // then
        assertEquals(TOKEN_NOT_FOUND.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(TOKEN_NOT_FOUND.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldFailM1MismatchCompletePasswordChange() {
        // given
        String A = Base64.getEncoder().encodeToString(BigInteger.TEN.toByteArray());
        UserEntity userEntity = userDao.findByUserId(userId);
        SrpRedisEntity srpRedisEntity = srpFlow.beginFlow(A, userEntity);
        UUID deviceId = UUID.randomUUID();
        PasswordChangeCompleteReq req = generatePasswordChangeCompleteReq(deviceId, "M1");
        String redisKey = RedisKeys.passwordChange(
                userEntity.getUserId().toString(),
                req.getDeviceId().toString()
        );
        redisService.save(
                redisKey,
                srpRedisEntity,
                Duration.of(10, ChronoUnit.SECONDS)
        );
        assertTrue(redisService.exists(redisKey));

        // when
        PasswordChangeException ex = assertThrows(
                PasswordChangeException.class,
                () -> passwordChangeService.completePasswordChange(userId, req)
        );

        // then
        assertEquals(SRP_VERIFICATION_FAILED.getHttpStatus(), ex.getErrorEnum().getHttpStatus());
        assertEquals(SRP_VERIFICATION_FAILED.getMessage(), ex.getErrorEnum().getMessage());
    }

    @Test
    void shouldSucceedCompletePasswordChange() {
        // given
        String A = Base64.getEncoder().encodeToString(BigInteger.TEN.toByteArray());
        UserEntity userEntity = userDao.findByUserId(userId);
        SrpRedisEntity srpRedisEntity = srpFlow.beginFlow(A, userEntity);
        BigInteger M1Client = srpFlow.calculateM1Server(srpRedisEntity);
        String M1 = Base64.getEncoder().encodeToString(M1Client.toByteArray());
        UUID deviceId = UUID.randomUUID();
        PasswordChangeCompleteReq req = generatePasswordChangeCompleteReq(deviceId, M1);
        String redisKey = RedisKeys.passwordChange(
                userEntity.getUserId().toString(),
                req.getDeviceId().toString()
        );
        redisService.save(
                redisKey,
                srpRedisEntity,
                Duration.of(10, ChronoUnit.SECONDS)
        );
        assertTrue(redisService.exists(redisKey));
        assertEquals(0, auditLogDao.findAll().size());

        // when
        ResponseEntity<Void> response = passwordChangeService.completePasswordChange(userId, req);

        // then
        userEntity = userDao.findByUserId(userId);
        assertFalse(redisService.exists(redisKey));
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userEntity.getVerifier(), req.getNewVerifier());
        assertEquals(1, auditLogDao.findAll().size());
    }

}
