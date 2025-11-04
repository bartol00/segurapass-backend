package com.security.passwordmanager.api.versions;

import lombok.Data;

import java.time.LocalDate;

@Data
public class VersionInfo {
    private String versionNumber, versionDescription;
    private LocalDate versionDate;
}
