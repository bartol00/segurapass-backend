package xyz.segurapass.backend.controller;

import xyz.segurapass.backend.config.AuthenticatedUser;
import xyz.segurapass.api.deletion.*;
import xyz.segurapass.backend.service.AccountDeletionService;
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
    ResponseEntity<AuthorizedDeletionStartResp> startAuthorizedDeletion(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestBody AuthorizedDeletionStartReq authorizedDeletionStartReq
    ) {
        return accountDeletionService.startAuthorizedDeletion(authenticatedUser.userId(), authorizedDeletionStartReq);
    }

    @PostMapping("/authorized/end")
    ResponseEntity<Void> completeAuthorizedDeletion(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestBody AuthorizedDeletionCompleteReq authorizedDeletionCompleteReq
    ) {
        return accountDeletionService.completeAuthorizedDeletion(authenticatedUser.userId(), authorizedDeletionCompleteReq);
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
