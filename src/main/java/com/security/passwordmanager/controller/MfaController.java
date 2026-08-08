package com.security.passwordmanager.controller;

import com.security.passwordmanager.config.AuthenticatedUser;
import com.security.passwordmanager.service.mfa.TotpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import xyz.segurapass.api.credentials.NonceResp;
import xyz.segurapass.api.mfa.TotpReq;
import xyz.segurapass.api.mfa.TotpResp;
import xyz.segurapass.api.mfa.TotpVerifyReq;
import xyz.segurapass.api.mfa.TotpVerifyResp;

import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mfa")
@Slf4j
public class MfaController {

    private final TotpService totpService;

    @GetMapping("/add-totp/start")
    public ResponseEntity<NonceResp> addTotpStart(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        log.info("Add TOTP Start - Controller");
        return totpService.addTotpStart(authenticatedUser.userId(), authenticatedUser.deviceId());
    }

    @PostMapping("/add-totp/end")
    public ResponseEntity<TotpResp> addTotpEnd(
            @RequestBody TotpReq req,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestHeader("X-SeguraPass-Signature") String signature
    ) {
        log.info("Add TOTP End - Controller");
        return totpService.addTotpEnd(req, authenticatedUser.userId(), authenticatedUser.deviceId(), signature);
    }

    @GetMapping("/remove-totp/start")
    public ResponseEntity<NonceResp> removeTotpStart(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        log.info("Remove TOTP Start - Controller");
        return totpService.removeTotpStart(authenticatedUser.userId(), authenticatedUser.deviceId());
    }

    @PostMapping("/remove-totp/end")
    public ResponseEntity<Void> removeTotpEnd(
            @RequestBody TotpReq req,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestHeader("X-SeguraPass-Signature") String signature
    ) {
        log.info("Remove TOTP End - Controller");
        return totpService.removeTotpEnd(req, authenticatedUser.userId(), authenticatedUser.deviceId(), signature);
    }

    @PostMapping("/verify-totp")
    public ResponseEntity<TotpVerifyResp> verifyTotp(
            @RequestBody TotpVerifyReq req,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        log.info("Verify TOTP - Controller");
        return totpService.verifyTotp(req, authenticatedUser.userId(), authenticatedUser.deviceId());
    }

}
