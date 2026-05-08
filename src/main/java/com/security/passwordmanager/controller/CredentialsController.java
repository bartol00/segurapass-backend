package com.security.passwordmanager.controller;

import xyz.segurapass.api.credentials.*;
import com.security.passwordmanager.service.CredentialsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/credentials")
@Slf4j
public class CredentialsController {

    private final CredentialsService credentialsService;

    @GetMapping("/get")
    public ResponseEntity<Page<CredentialsResp>> getCredentials(@AuthenticationPrincipal UUID userId, @RequestParam(defaultValue = "0") int page,
                                                                @RequestParam(defaultValue = "20") int size) {
        log.info("Get Credentials - Controller");
        return credentialsService.getCredentials(userId, page, size);
    }

    @GetMapping("/get/{id}")
    public ResponseEntity<CredentialsResp> getCredentialById(@PathVariable UUID id, @AuthenticationPrincipal UUID userId) {
        log.info("Get Credentials By ID - Controller");
        return credentialsService.getCredentialById(id, userId);
    }

    @PostMapping("/create")
    public ResponseEntity<CredentialsResp> createCredentials(@RequestBody CredentialsReq req, @AuthenticationPrincipal UUID userId) {
        log.info("Create Credentials - Controller");
        return credentialsService.createCredentials(req, userId);
    }

    @PutMapping("/update/{id}")
    public ResponseEntity<CredentialsResp> updateCredentials(@PathVariable UUID id, @RequestBody CredentialsReq req, @AuthenticationPrincipal UUID userId) {
        log.info("Update Credentials - Controller");
        return credentialsService.updateCredentials(id, req, userId);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<Void> deleteCredentials(@PathVariable UUID id, @AuthenticationPrincipal UUID userId) {
        log.info("Delete Credentials - Controller");
        return credentialsService.deleteCredentials(id, userId);
    }

}
