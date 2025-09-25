package com.security.passwordmanager.config;

import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.FileReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Configuration
public class KeyLoaderBC {

    @Value("${app.security.private-key-path}")
    private String privateKeyPath;

    @Value("${app.security.public-key-path}")
    private String publicKeyPath;

    @Bean
    public PrivateKey privateKey() throws Exception {
        try (PemReader pemReader = new PemReader(new FileReader(privateKeyPath))) {
            byte[] content = pemReader.readPemObject().getContent();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(content);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        }
    }

    @Bean
    public PublicKey publicKey() throws Exception {
        try (PemReader pemReader = new PemReader(new FileReader(publicKeyPath))) {
            byte[] content = pemReader.readPemObject().getContent();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(content);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        }
    }
}
