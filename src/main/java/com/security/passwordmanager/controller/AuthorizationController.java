package com.security.passwordmanager.controller;

import com.security.passwordmanager.api.authorization.*;
import com.security.passwordmanager.service.AuthorizationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/authorization")
public class AuthorizationController {

    private final AuthorizationService authorizationService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegistrationReq req) {
        return authorizationService.registerUser(req);
    }

    @PostMapping("/login/start")
    public ResponseEntity<?> loginUserStart(@RequestBody LoginStartReq req) {
        return authorizationService.loginUserStart(req);
    }

    @PostMapping("/login/end")
    public ResponseEntity<?> loginUserEnd(@RequestBody LoginCompleteReq req) {
        return authorizationService.loginUserEnd(req);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshJWT(RefreshReq req) {
        return authorizationService.refreshJWT(req);
    }

}
