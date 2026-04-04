package com.security.passwordmanager.controller;

import com.security.passwordmanager.api.authorization.*;
import com.security.passwordmanager.service.AuthorizationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/authorization")
public class AuthorizationController {

    private final AuthorizationService authorizationService;

    @PostMapping("/register")
    public ResponseEntity<Void> registerUser(@RequestBody RegistrationReq req) {
        return authorizationService.registerUser(req);
    }

    @PostMapping("/login/start")
    public ResponseEntity<LoginStartResp> loginUserStart(@RequestBody LoginStartReq req) {
        return authorizationService.loginUserStart(req);
    }

    @PostMapping("/login/end")
    public ResponseEntity<LoginCompleteResp> loginUserEnd(@RequestBody LoginCompleteReq req) {
        return authorizationService.loginUserEnd(req);
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshResp> refreshJWT(@RequestBody RefreshReq req) {
        return authorizationService.refreshJWT(req);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody RefreshReq req) {
        return authorizationService.logout(req);
    }

    @GetMapping("/verify/{token}")
    public ResponseEntity<String> verifyEmail(@PathVariable String token) {
        return authorizationService.verifyEmail(token);
    }

}
