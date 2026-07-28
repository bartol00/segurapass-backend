package com.security.passwordmanager.controller;

import com.security.passwordmanager.config.AuthenticatedUser;
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
    public ResponseEntity<Page<CredentialsResp>> getCredentials(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        log.info("Get Credentials - Controller");
        return credentialsService.getCredentials(authenticatedUser.userId(), page, size);
    }

    @GetMapping("/get/{id}")
    public ResponseEntity<CredentialsResp> getCredentialById(
            @PathVariable UUID id,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        log.info("Get Credentials By ID - Controller");
        return credentialsService.getCredentialById(id, authenticatedUser.userId());
    }

    @GetMapping("/create/start")
    public ResponseEntity<NonceResp> createCredentialsStart(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        log.info("Create Credentials Start - Controller");
        return credentialsService.createCredentialsStart(authenticatedUser.userId(), authenticatedUser.deviceId());
    }

    @PostMapping("/create/end")
    public ResponseEntity<CredentialsResp> createCredentialsEnd(
            @RequestBody CredentialsReq req,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestHeader("X-SeguraPass-Signature") String signature
    ) {
        log.info("Create Credentials End - Controller");
        return credentialsService.createCredentialsEnd(req, authenticatedUser.userId(), authenticatedUser.deviceId(), signature);
    }

    @GetMapping("/update/start/{id}")
    public ResponseEntity<NonceResp> updateCredentialsStart(
            @PathVariable UUID id,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        log.info("Update Credentials Start - Controller");
        return credentialsService.updateCredentialsStart(id, authenticatedUser.userId(), authenticatedUser.deviceId());
    }

    @PutMapping("/update/end/{id}")
    public ResponseEntity<CredentialsResp> updateCredentialsEnd(
            @PathVariable UUID id,
            @RequestBody CredentialsReq req,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestHeader("X-SeguraPass-Signature") String signature
    ) {
        log.info("Update Credentials End - Controller");
        return credentialsService.updateCredentialsEnd(id, req, authenticatedUser.userId(), authenticatedUser.deviceId(), signature);
    }

    @GetMapping("/delete/start/{id}")
    public ResponseEntity<NonceResp> deleteCredentialsStart(
            @PathVariable UUID id,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        log.info("Delete Credentials Start - Controller");
        return credentialsService.deleteCredentialsStart(id, authenticatedUser.userId(), authenticatedUser.deviceId());
    }

    @PostMapping("/delete/end/{id}")
    public ResponseEntity<Void> deleteCredentialsEnd(
            @PathVariable UUID id,
            @RequestBody CredentialsReq req,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestHeader("X-SeguraPass-Signature") String signature
    ) {
        log.info("Delete Credentials End - Controller");
        return credentialsService.deleteCredentialsEnd(id, req, authenticatedUser.userId(), authenticatedUser.deviceId(), signature);
    }

}
