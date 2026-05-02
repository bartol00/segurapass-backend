package com.security.passwordmanager.config;

import com.security.passwordmanager.api.email.EmailReq;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class EmailClient {

    private final WebClient webClient;

    public EmailClient(@Value("${app.email.url}") String emailUrl) {
        this.webClient = WebClient.builder()
                .baseUrl(emailUrl)
                .build();
    }

    public void sendEmail(EmailReq req) {
        webClient.post()
                .uri("/send-email")
                .bodyValue(req)
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }

}
