package com.security.passwordmanager.config;

import org.springframework.stereotype.Component;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class UserKeyLoader {

    public static PublicKey getPublicKeyFromBase64(String publicKeyB64) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(publicKeyB64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static boolean verifySignature(PublicKey publicKey, byte[] nonceBytes, byte[] signatureBytes) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(nonceBytes);

        return verifier.verify(signatureBytes);
    }

}
