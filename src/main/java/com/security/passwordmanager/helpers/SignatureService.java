package com.security.passwordmanager.helpers;

import java.security.PublicKey;
import java.util.UUID;

public interface SignatureService {
    PublicKey getPublicKey(UUID userId) throws Exception;
    boolean verifySignature(PublicKey publicKey, byte[] payload, String signatureBase64) throws Exception;
}
