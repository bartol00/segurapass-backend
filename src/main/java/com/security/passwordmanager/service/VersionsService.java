package com.security.passwordmanager.service;

import xyz.segurapass.api.versions.VersionInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.time.LocalDate;

@Service
@Slf4j
public class VersionsService {

    @Value("${app.latest.version}")
    private String versionNumber;

    @Value("${app.latest.description}")
    private String versionDescription;

    @Value("${app.latest.update-time}")
    private String versionDate;

    @Value("${app.latest.download-url}")
    private String downloadUrl;

    public ResponseEntity<VersionInfo> getLatestVersion() {
        VersionInfo versionInfo = new VersionInfo(
                versionNumber,
                versionDescription,
                downloadUrl,
                LocalDate.parse(versionDate)
        );

        log.info("Get Latest Version - Service");

        return ResponseEntity.ok(versionInfo);
    }

}
