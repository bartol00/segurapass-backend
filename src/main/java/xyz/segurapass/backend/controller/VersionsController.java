package xyz.segurapass.backend.controller;

import xyz.segurapass.api.versions.VersionInfo;
import xyz.segurapass.backend.service.VersionsService;
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

    @GetMapping
    public ResponseEntity<VersionInfo> getLatestVersion() {
        return versionsService.getLatestVersion();
    }

}
