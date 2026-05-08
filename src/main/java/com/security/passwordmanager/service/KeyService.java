package com.security.passwordmanager.service;

import xyz.segurapass.api.key.PublicKeyResp;
import com.security.passwordmanager.exceptions.KeysException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;

import static com.security.passwordmanager.exceptions.ErrorEnum.PUBLIC_KEY_NOT_READ;

@Service
@Slf4j
@Profile("!test")
public class KeyService {

    @Value("${app.security.public-key-path}")
    private String publicKeyPath;

    public ResponseEntity<PublicKeyResp> getPublicKey() {
        try {
            String pem = Files.readString(Path.of(publicKeyPath));
            log.info("Public key found");
            PublicKeyResp resp = new PublicKeyResp();
            resp.setPublicKey(pem);
            return ResponseEntity.ok(resp);
        } catch (Exception e) {
            log.error("Public key could not be found");
            throw new KeysException(PUBLIC_KEY_NOT_READ);
        }
    }

}
