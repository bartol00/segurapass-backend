package com.security.passwordmanager.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/uptime")
public class UptimeController {

    @GetMapping
    public ResponseEntity<Void> isUp() {
        return ResponseEntity.ok().build();
    }

}
