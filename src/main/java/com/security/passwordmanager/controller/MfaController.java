package com.security.passwordmanager.controller;

import com.security.passwordmanager.config.AuthenticatedUser;
import com.security.passwordmanager.service.mfa.TotpService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import xyz.segurapass.api.authorization.LoginCompleteResp;
import xyz.segurapass.api.credentials.NonceResp;
import xyz.segurapass.api.mfa.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mfa")
public class MfaController {

    private final TotpService totpService;

    @GetMapping("/add-totp/start")
    public ResponseEntity<NonceResp> addTotpStart(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        return totpService.addTotpStart(authenticatedUser.userId(), authenticatedUser.deviceId());
    }

    @PostMapping("/add-totp/end")
    public ResponseEntity<TotpResp> addTotpEnd(
            @RequestBody TotpReq req,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestHeader("X-SeguraPass-Signature") String signature
    ) {
        return totpService.addTotpEnd(req, authenticatedUser.userId(), authenticatedUser.deviceId(), signature);
    }

    @GetMapping("/remove-totp/start")
    public ResponseEntity<NonceResp> removeTotpStart(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        return totpService.removeTotpStart(authenticatedUser.userId(), authenticatedUser.deviceId());
    }

    @PostMapping("/remove-totp/end")
    public ResponseEntity<Void> removeTotpEnd(
            @RequestBody TotpReq req,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestHeader("X-SeguraPass-Signature") String signature
    ) {
        return totpService.removeTotpEnd(req, authenticatedUser.userId(), authenticatedUser.deviceId(), signature);
    }

    @PostMapping("/verify-totp")
    public ResponseEntity<TotpVerifyResp> verifyTotp(
            @RequestBody TotpVerifyReq req,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        return totpService.verifyTotp(req, authenticatedUser.userId(), authenticatedUser.deviceId());
    }

    @PostMapping("/login-totp/{code}")
    public ResponseEntity<LoginCompleteResp> loginTotp(
            @PathVariable String code,
            @RequestBody TotpVerifyReq req
    ) {
        return totpService.totpLogin(code, req);
    }

    @PostMapping("/recovery-totp/{code}")
    public ResponseEntity<LoginCompleteResp> recoveryTotp(
            @PathVariable String code,
            @RequestBody TotpRecoveryReq req
    ) {
        return totpService.totpLoginMfaRecovery(code, req);
    }

}
