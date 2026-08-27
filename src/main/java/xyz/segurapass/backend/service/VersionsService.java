package xyz.segurapass.backend.service;

import xyz.segurapass.api.versions.VersionInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class VersionsService {

    @Value("${app.app-version}")
    private String appVersion;

    @Value("${app.protocol-version}")
    private String protocolVersion;

    public ResponseEntity<VersionInfo> getLatestVersion() {
        VersionInfo versionInfo = new VersionInfo(
                appVersion,
                protocolVersion
        );
        return ResponseEntity.ok(versionInfo);
    }

}
