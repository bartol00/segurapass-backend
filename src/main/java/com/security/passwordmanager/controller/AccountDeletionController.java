package com.security.passwordmanager.controller;

import com.security.passwordmanager.api.deletion.AuthorizedDeletionCompleteReq;
import com.security.passwordmanager.api.deletion.AuthorizedDeletionStartReq;
import com.security.passwordmanager.api.deletion.AuthorizedDeletionStartResp;
import com.security.passwordmanager.api.deletion.EmailDeletionStartReq;
import com.security.passwordmanager.service.AccountDeletionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/deletion")
public class AccountDeletionController {

    private final AccountDeletionService accountDeletionService;

    @PostMapping("/authorized/start")
    ResponseEntity<AuthorizedDeletionStartResp> startAuthorizedDeletion(@AuthenticationPrincipal String email, @RequestBody AuthorizedDeletionStartReq authorizedDeletionStartReq) {
        return accountDeletionService.startAuthorizedDeletion(email, authorizedDeletionStartReq);
    }

    @PostMapping("/authorized/end")
    ResponseEntity<Void> completeAuthorizedDeletion(@AuthenticationPrincipal String email, @RequestBody AuthorizedDeletionCompleteReq authorizedDeletionCompleteReq) {
        return accountDeletionService.completeAuthorizedDeletion(email, authorizedDeletionCompleteReq);
    }

    @PostMapping("/email/start")
    ResponseEntity<Void> startDeletionEmail(@RequestBody EmailDeletionStartReq req) {
        accountDeletionService.startDeletionEmail(req);
        return ResponseEntity.ok(null);
    }

    @GetMapping("/email/end/{token}")
    ResponseEntity<String> completeDeletionEmail(@PathVariable String token) {
        return accountDeletionService.completeDeletionEmail(token);
    }

}
