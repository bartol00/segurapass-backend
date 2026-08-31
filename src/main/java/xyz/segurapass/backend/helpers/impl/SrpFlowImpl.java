package xyz.segurapass.backend.helpers.impl;

import xyz.segurapass.backend.helpers.SrpFlow;
import xyz.segurapass.backend.model.authorization.UserEntity;
import xyz.segurapass.backend.redis.entities.SrpRedisEntity;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class SrpFlowImpl implements SrpFlow {

    private final SRP6GroupParameters group = SRP6StandardGroups.rfc5054_3072;
    private final Digest digest = new SHA256Digest();
    private final SecureRandom random = new SecureRandom();
    private final BigInteger N = group.getN();
    private final BigInteger g = group.getG();

    @Override
    public SrpRedisEntity beginFlow(String A, UserEntity userEntity) {
        BigInteger k = SRP6Util.calculateK(digest, N, g);

        BigInteger v = new BigInteger(1, Base64.getDecoder().decode(userEntity.getVerifier()));
        BigInteger b = new BigInteger(256, random);
        BigInteger B = k.multiply(v).add(g.modPow(b, N)).mod(N);

        return new SrpRedisEntity(
                A,
                Base64.getEncoder().encodeToString(b.toByteArray()),
                Base64.getEncoder().encodeToString(B.toByteArray()),
                Base64.getEncoder().encodeToString(v.toByteArray())
        );
    }

    @Override
    public BigInteger calculateM1Server(SrpRedisEntity srpRedisEntity) {
        BigInteger A = new BigInteger(1, Base64.getDecoder().decode(srpRedisEntity.getA()));
        BigInteger B = new BigInteger(1, Base64.getDecoder().decode(srpRedisEntity.getB()));
        BigInteger b = new BigInteger(1, Base64.getDecoder().decode(srpRedisEntity.getBpriv()));
        BigInteger v = new BigInteger(1, Base64.getDecoder().decode(srpRedisEntity.getVerifier()));

        BigInteger u = SRP6Util.calculateU(digest, N, A, B);
        BigInteger S = A.multiply(v.modPow(u, N)).modPow(b, N);

        return SRP6Util.calculateM1(digest, N, A, B, S);
    }

    @Override
    public BigInteger calculateM2Server(SrpRedisEntity srpRedisEntity, BigInteger M1Client) {
        BigInteger A = new BigInteger(1, Base64.getDecoder().decode(srpRedisEntity.getA()));
        BigInteger B = new BigInteger(1, Base64.getDecoder().decode(srpRedisEntity.getB()));
        BigInteger b = new BigInteger(1, Base64.getDecoder().decode(srpRedisEntity.getBpriv()));
        BigInteger v = new BigInteger(1, Base64.getDecoder().decode(srpRedisEntity.getVerifier()));

        BigInteger u = SRP6Util.calculateU(digest, N, A, B);
        BigInteger S = A.multiply(v.modPow(u, N)).modPow(b, N);

        return SRP6Util.calculateM2(digest, A, M1Client, S, B);
    }
}
