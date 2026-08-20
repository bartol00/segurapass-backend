package com.security.passwordmanager.helpers.impl;

import com.security.passwordmanager.helpers.SignatureService;
import com.security.passwordmanager.model.authorization.UserDao;
import com.security.passwordmanager.redis.RedisKeys;
import com.security.passwordmanager.redis.RedisService;
import com.security.passwordmanager.redis.entities.UserPublicKeyEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

@Component
public class SignatureServiceImpl implements SignatureService {

    @Autowired
    private UserDao userDao;
    @Autowired
    private RedisService redisService;

    @Override
    public PublicKey getPublicKey(UUID userId) throws Exception {
        String redisKey = RedisKeys.userPublicKey(userId.toString());
        KeyFactory factory = KeyFactory.getInstance("Ed25519");

        if (redisService.exists(redisKey)) {
            UserPublicKeyEntity userPublicKeyEntity = redisService.get(redisKey, UserPublicKeyEntity.class);
            return factory.generatePublic(
                    new X509EncodedKeySpec(userPublicKeyEntity.getPublicKeyBytes())
            );
        } else {
            byte[] publicKeyBytes = userDao.findByUserId(userId).getPublicSigningKeyBytes();

            UserPublicKeyEntity userPublicKeyEntity = new UserPublicKeyEntity(publicKeyBytes);
            redisService.save(redisKey, userPublicKeyEntity, Duration.of(10, ChronoUnit.MINUTES));

            return factory.generatePublic(
                    new X509EncodedKeySpec(publicKeyBytes)
            );
        }
    }

    @Override
    public boolean verifySignature(PublicKey publicKey, byte[] payload, String signatureBase64) throws Exception {
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(publicKey);
        signature.update(payload);

        return signature.verify(signatureBytes);
    }

}
