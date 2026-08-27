package xyz.segurapass.backend.service;

import xyz.segurapass.api.key.PublicKeyResp;
import xyz.segurapass.backend.exceptions.KeysException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;

import static xyz.segurapass.backend.exceptions.enums.ErrorEnum.PUBLIC_KEY_NOT_READ;

@Service
@Slf4j
@Profile("!test")
public class KeyService {

    private final String publicKeyPem;

    public KeyService(@Value("${app.security.public-key-path}") String publicKeyPath) {
        try {
            this.publicKeyPem = Files.readString(Path.of(publicKeyPath));
            log.info("Public key found");
        } catch (Exception e) {
            log.error("Public key could not be found");
            throw new KeysException(PUBLIC_KEY_NOT_READ);
        }
    }

    public ResponseEntity<PublicKeyResp> getPublicKey() {
        PublicKeyResp resp = new PublicKeyResp(publicKeyPem);
        return ResponseEntity.ok(resp);
    }

}
