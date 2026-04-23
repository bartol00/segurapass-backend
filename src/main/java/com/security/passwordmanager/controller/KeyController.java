package com.security.passwordmanager.controller;

import com.security.passwordmanager.api.key.PublicKeyResp;
import com.security.passwordmanager.service.KeyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/.well-known")
@Slf4j
@Profile("!test")
public class KeyController {

    private final KeyService keyService;

    @GetMapping("/public-key")
    public ResponseEntity<PublicKeyResp> getPublicKey() {
        log.info("Public key call - Controller");
        return keyService.getPublicKey();
    }

}
