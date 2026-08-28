package xyz.segurapass.backend.service;

import org.springframework.beans.factory.annotation.Autowired;
import xyz.segurapass.api.versions.VersionInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import xyz.segurapass.backend.config.EmailClient;

@Service
public class VersionsService {

    @Value("${app.app-version}")
    private String appVersion;

    @Value("${app.protocol-version}")
    private String protocolVersion;

    @Autowired
    private EmailClient emailClient;

    public ResponseEntity<VersionInfo> getLatestVersion() {
        VersionInfo versionInfo = new VersionInfo(
                appVersion,
                protocolVersion,
                emailClient.isActive()
        );
        return ResponseEntity.ok(versionInfo);
    }

}
