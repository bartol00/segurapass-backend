package com.security.passwordmanager.controller;

import com.security.passwordmanager.api.versions.VersionInfo;
import com.security.passwordmanager.service.VersionsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/versions")
public class VersionsController {

    private final VersionsService versionsService;

    @GetMapping("/latest")
    public ResponseEntity<VersionInfo> getLatestVersion() {
        return versionsService.getLatestVersion();
    }

}
