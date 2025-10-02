package com.security.passwordmanager.controller;

import com.security.passwordmanager.api.credentials.CredentialsReq;
import com.security.passwordmanager.service.CredentialsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/credentials")
public class CredentialsController {

    private final CredentialsService credentialsService;

    @GetMapping("/get")
    public ResponseEntity<?> getCredentials(@AuthenticationPrincipal String email, @RequestParam(defaultValue = "0") int page,
                                            @RequestParam(defaultValue = "20") int size) {
        System.out.println("Controller email: " + email);
        return credentialsService.getCredentials(email, page, size);
    }

    @GetMapping("/get/{id}")
    public ResponseEntity<?> getCredentialById(@PathVariable UUID id, @AuthenticationPrincipal String email) {
        return credentialsService.getCredentialById(id, email);
    }

    @PostMapping("/create")
    public ResponseEntity<?> createCredentials(@RequestBody CredentialsReq req, @AuthenticationPrincipal String email) {
        return credentialsService.createCredentials(req, email);
    }

    @PatchMapping("/update/{id}")
    public ResponseEntity<?> updateCredentials(@PathVariable UUID id, @RequestBody CredentialsReq req, @AuthenticationPrincipal String email) {
        return credentialsService.updateCredentials(id, req, email);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> deleteCredentials(@PathVariable UUID id, @AuthenticationPrincipal String email) {
        return credentialsService.deleteCredentials(id, email);
    }

}
