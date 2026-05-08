package com.security.passwordmanager.controller;

import xyz.segurapass.api.versions.VersionInfo;
import com.security.passwordmanager.service.VersionsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/versions")
@Slf4j
public class VersionsController {

    private final VersionsService versionsService;

    @GetMapping("/latest")
    public ResponseEntity<VersionInfo> getLatestVersion() {
        log.info("Get Latest Version - Controller");
        return versionsService.getLatestVersion();
    }

}
