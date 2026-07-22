package com.security.passwordmanager.controller;

import com.security.passwordmanager.config.AuthenticatedUser;
import xyz.segurapass.api.deletion.*;
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
    ResponseEntity<AuthorizedDeletionStartResp> startAuthorizedDeletion(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestBody AuthorizedDeletionStartReq authorizedDeletionStartReq
    ) {
        log.info("Start Authorized Deletion - Controller");
        return accountDeletionService.startAuthorizedDeletion(authenticatedUser.userId(), authorizedDeletionStartReq);
    }

    @PostMapping("/authorized/end")
    ResponseEntity<Void> completeAuthorizedDeletion(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestBody AuthorizedDeletionCompleteReq authorizedDeletionCompleteReq
    ) {
        log.info("Complete Authorized Deletion - Controller");
        return accountDeletionService.completeAuthorizedDeletion(authenticatedUser.userId(), authorizedDeletionCompleteReq);
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
