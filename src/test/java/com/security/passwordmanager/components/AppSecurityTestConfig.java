package com.security.passwordmanager.components;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

@TestConfiguration
public class AppSecurityTestConfig {

    private final KeyPair keyPair;
    private final String emailHashSalt;

    public AppSecurityTestConfig() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        this.keyPair = keyGen.generateKeyPair();
        this.emailHashSalt = UUID.randomUUID().toString();
    }

    @Bean
    @Primary
    public PrivateKey secretKey() {
        return keyPair.getPrivate();
    }

    @Bean
    @Primary
    public PublicKey publicKey() {
        return keyPair.getPublic();
    }

    @Bean
    @Primary
    @Qualifier("emailHashSalt")
    public String emailHashSalt() {
        return emailHashSalt;
    }
}