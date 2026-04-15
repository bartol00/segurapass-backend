package com.security.passwordmanager.components;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

@TestConfiguration
public class TestKeyLoaderComponent {

    private KeyPair keyPair;

    public TestKeyLoaderComponent() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        this.keyPair = keyGen.generateKeyPair();
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
}