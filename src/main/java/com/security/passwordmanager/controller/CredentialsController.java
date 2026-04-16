package com.security.passwordmanager.controller;

import com.security.passwordmanager.api.credentials.CredentialsReq;
import com.security.passwordmanager.api.credentials.CredentialsResp;
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
    public ResponseEntity<Page<CredentialsResp>> getCredentials(@AuthenticationPrincipal String email, @RequestParam(defaultValue = "0") int page,
                                                                @RequestParam(defaultValue = "20") int size) {
        log.info("Get Credentials - Controller");
        return credentialsService.getCredentials(email, page, size);
    }

    @GetMapping("/get/{id}")
    public ResponseEntity<CredentialsResp> getCredentialById(@PathVariable UUID id, @AuthenticationPrincipal String email) {
        log.info("Get Credentials By ID - Controller");
        return credentialsService.getCredentialById(id, email);
    }

    @PostMapping("/create")
    public ResponseEntity<CredentialsResp> createCredentials(@RequestBody CredentialsReq req, @AuthenticationPrincipal String email) {
        log.info("Create Credentials - Controller");
        return credentialsService.createCredentials(req, email);
    }

    @PutMapping("/update/{id}")
    public ResponseEntity<CredentialsResp> updateCredentials(@PathVariable UUID id, @RequestBody CredentialsReq req, @AuthenticationPrincipal String email) {
        log.info("Update Credentials - Controller");
        return credentialsService.updateCredentials(id, req, email);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<Void> deleteCredentials(@PathVariable UUID id, @AuthenticationPrincipal String email) {
        log.info("Delete Credentials - Controller");
        return credentialsService.deleteCredentials(id, email);
    }

}
