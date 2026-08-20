package com.security.passwordmanager.controller;

import xyz.segurapass.api.key.PublicKeyResp;
import com.security.passwordmanager.service.KeyService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/.well-known")
@Profile("!test")
public class KeyController {

    private final KeyService keyService;

    @GetMapping("/public-key")
    public ResponseEntity<PublicKeyResp> getPublicKey() {
        return keyService.getPublicKey();
    }

}
