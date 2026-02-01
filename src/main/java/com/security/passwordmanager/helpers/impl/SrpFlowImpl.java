package com.security.passwordmanager.helpers.impl;

import com.security.passwordmanager.helpers.SrpFlow;
import com.security.passwordmanager.model.authorization.SrpEntity;
import com.security.passwordmanager.model.authorization.UserEntity;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

@Component
public class SrpFlowImpl implements SrpFlow {

    private final SRP6GroupParameters group = SRP6StandardGroups.rfc5054_3072;
    private final Digest digest = new SHA256Digest();
    private final SecureRandom random = new SecureRandom();
    private final BigInteger N = group.getN();
    private final BigInteger g = group.getG();

    @Override
    public SrpEntity beginFlow(String A, UUID deviceId, UserEntity userEntity) {
        BigInteger k = SRP6Util.calculateK(digest, N, g);

        BigInteger v = new BigInteger(1, Base64.getDecoder().decode(userEntity.getVerifier()));
        BigInteger b = new BigInteger(256, random);
        BigInteger B = k.multiply(v).add(g.modPow(b, N)).mod(N);

        SrpEntity srpEntity = new SrpEntity();
        srpEntity.setA(A);
        srpEntity.setBpriv(Base64.getEncoder().encodeToString(b.toByteArray()));
        srpEntity.setB(Base64.getEncoder().encodeToString(B.toByteArray()));
        srpEntity.setVerifier(Base64.getEncoder().encodeToString(v.toByteArray()));
        srpEntity.setDeviceId(deviceId);
        srpEntity.setUserEntity(userEntity);
        srpEntity.setExpiryTime(Instant.now().plus(60, ChronoUnit.SECONDS));

        return srpEntity;
    }

    @Override
    public BigInteger calculateM1Server(SrpEntity srpEntity) {
        BigInteger A = new BigInteger(1, Base64.getDecoder().decode(srpEntity.getA()));
        BigInteger B = new BigInteger(1, Base64.getDecoder().decode(srpEntity.getB()));
        BigInteger b = new BigInteger(1, Base64.getDecoder().decode(srpEntity.getBpriv()));
        BigInteger v = new BigInteger(1, Base64.getDecoder().decode(srpEntity.getVerifier()));

        BigInteger u = SRP6Util.calculateU(digest, N, A, B);
        BigInteger S = A.multiply(v.modPow(u, N)).modPow(b, N);

        return SRP6Util.calculateM1(digest, N, A, B, S);
    }

    @Override
    public BigInteger calculateM2Server(SrpEntity srpEntity, BigInteger M1Client) {
        BigInteger A = new BigInteger(1, Base64.getDecoder().decode(srpEntity.getA()));
        BigInteger B = new BigInteger(1, Base64.getDecoder().decode(srpEntity.getB()));
        BigInteger b = new BigInteger(1, Base64.getDecoder().decode(srpEntity.getBpriv()));
        BigInteger v = new BigInteger(1, Base64.getDecoder().decode(srpEntity.getVerifier()));

        BigInteger u = SRP6Util.calculateU(digest, N, A, B);
        BigInteger S = A.multiply(v.modPow(u, N)).modPow(b, N);

        return SRP6Util.calculateM2(digest, A, M1Client, S, B);
    }
}
