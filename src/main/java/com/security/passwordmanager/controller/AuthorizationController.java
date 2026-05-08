package com.security.passwordmanager.controller;

import xyz.segurapass.api.authorization.*;
import com.security.passwordmanager.service.AuthorizationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/authorization")
@Slf4j
public class AuthorizationController {

    private final AuthorizationService authorizationService;

    @PostMapping("/register")
    public ResponseEntity<Void> registerUser(@RequestBody RegistrationReq req) {
        log.info("Register User - Controller");
        return authorizationService.registerUser(req);
    }

    @PostMapping("/login/start")
    public ResponseEntity<LoginStartResp> loginUserStart(@RequestBody LoginStartReq req) {
        log.info("Login Start - Controller");
        return authorizationService.loginUserStart(req);
    }

    @PostMapping("/login/end")
    public ResponseEntity<LoginCompleteResp> loginUserEnd(@RequestBody LoginCompleteReq req) {
        log.info("Login Complete - Controller");
        return authorizationService.loginUserEnd(req);
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshResp> refreshJWT(@RequestBody RefreshReq req) {
        log.info("JWT Refresh - Controller");
        return authorizationService.refreshJWT(req);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody RefreshReq req) {
        log.info("Logout - Controller");
        return authorizationService.logout(req);
    }

    @GetMapping("/verify/{token}")
    public ResponseEntity<String> verifyEmail(@PathVariable String token) {
        log.info("Email Verification - Controller");
        return authorizationService.verifyEmail(token);
    }

}
