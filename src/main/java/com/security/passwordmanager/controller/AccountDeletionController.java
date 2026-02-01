package com.security.passwordmanager.controller;

import com.security.passwordmanager.api.deletion.EmailDeletionStartReq;
import com.security.passwordmanager.service.AccountDeletionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/deletion")
public class AccountDeletionController {

    private final AccountDeletionService accountDeletionService;


    @PostMapping("/email/start")
    ResponseEntity<Void> startDeletionEmail(@RequestBody EmailDeletionStartReq req) {
        accountDeletionService.startDeletionEmail(req);
        return ResponseEntity.ok(null);
    }

    @GetMapping("/email/end/{token}")
    ResponseEntity<?> completeDeletionEmail(@PathVariable String token) {
        return accountDeletionService.completeDeletionEmail(token);
    }

}
