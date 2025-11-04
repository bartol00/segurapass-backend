package com.security.passwordmanager.service;

import com.security.passwordmanager.api.versions.VersionInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.time.LocalDate;

@Service
public class VersionsService {

    @Value("${app.latest.version}")
    private String versionNumber;

    @Value("${app.latest.description}")
    private String versionDescription;

    @Value("${app.latest.update-time}")
    private String versionDate;

    public ResponseEntity<VersionInfo> getLatestVersion() {
        VersionInfo versionInfo = new VersionInfo();
        versionInfo.setVersionNumber(versionNumber);
        versionInfo.setVersionDescription(versionDescription);
        versionInfo.setVersionDate(LocalDate.parse(versionDate));
        return ResponseEntity.ok(versionInfo);
    }

}
