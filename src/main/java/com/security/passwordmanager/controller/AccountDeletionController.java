package com.security.passwordmanager.controller;

import com.security.passwordmanager.api.deletion.AuthorizedDeletionCompleteReq;
import com.security.passwordmanager.api.deletion.AuthorizedDeletionStartReq;
import com.security.passwordmanager.api.deletion.AuthorizedDeletionStartResp;
import com.security.passwordmanager.api.deletion.EmailDeletionStartReq;
import com.security.passwordmanager.service.AccountDeletionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/deletion")
@Slf4j
public class AccountDeletionController {

    private final AccountDeletionService accountDeletionService;

    @PostMapping("/authorized/start")
    ResponseEntity<AuthorizedDeletionStartResp> startAuthorizedDeletion(@AuthenticationPrincipal String email, @RequestBody AuthorizedDeletionStartReq authorizedDeletionStartReq) {
        log.info("Start Authorized Deletion - Controller");
        return accountDeletionService.startAuthorizedDeletion(email, authorizedDeletionStartReq);
    }

    @PostMapping("/authorized/end")
    ResponseEntity<Void> completeAuthorizedDeletion(@AuthenticationPrincipal String email, @RequestBody AuthorizedDeletionCompleteReq authorizedDeletionCompleteReq) {
        log.info("Complete Authorized Deletion - Controller");
        return accountDeletionService.completeAuthorizedDeletion(email, authorizedDeletionCompleteReq);
    }

    @PostMapping("/email/start")
    ResponseEntity<Void> startDeletionEmail(@RequestBody EmailDeletionStartReq req) {
        log.info("Start Email Deletion - Controller");
        accountDeletionService.startDeletionEmail(req);
        return ResponseEntity.ok(null);
    }

    @GetMapping("/email/end/{token}")
    ResponseEntity<String> completeDeletionEmail(@PathVariable String token) {
        log.info("Complete Email Deletion - Controller");
        return accountDeletionService.completeDeletionEmail(token);
    }

}
