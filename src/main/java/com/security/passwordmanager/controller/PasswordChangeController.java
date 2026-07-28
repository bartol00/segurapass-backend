package com.security.passwordmanager.controller;

import com.security.passwordmanager.config.AuthenticatedUser;
import com.security.passwordmanager.service.PasswordChangeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import xyz.segurapass.api.password.*;

@RestController
@RequestMapping("/api/password")
@RequiredArgsConstructor
@Slf4j
public class PasswordChangeController {

    private final PasswordChangeService passwordChangeService;

    @PostMapping("/change/start")
    ResponseEntity<PasswordChangeStartResp> startPasswordChange(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestBody PasswordChangeStartReq passwordChangeStartReq
    ) {
        log.info("Start Password Change - Controller");
        return passwordChangeService.startPasswordChange(authenticatedUser.userId(), passwordChangeStartReq);
    }

    @PostMapping("/change/end")
    ResponseEntity<Void> completePasswordChange(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestBody PasswordChangeCompleteReq passwordChangeCompleteReq
    ) {
        log.info("Complete Password Change - Controller");
        return passwordChangeService.completePasswordChange(authenticatedUser.userId(), passwordChangeCompleteReq);
    }

}
