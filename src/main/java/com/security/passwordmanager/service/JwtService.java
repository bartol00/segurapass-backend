package com.security.passwordmanager.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public JwtService(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public String generateToken(String userIdString, Map<String, Object> additionalClaims, long expirationSeconds) {
        Instant now = Instant.now();
        return Jwts.builder()
                .claims(additionalClaims)
                .subject(userIdString)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(expirationSeconds)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public Claims validateToken(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
