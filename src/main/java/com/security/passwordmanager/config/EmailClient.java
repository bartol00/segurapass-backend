package com.security.passwordmanager.config;

import xyz.segurapass.api.email.EmailReq;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class EmailClient {

    private final WebClient webClient;
    private final boolean active;

    public EmailClient(
            @Value("${app.email.url}") String emailUrl,
            @Value("${app.email.active}") boolean active) {
        this.webClient = WebClient.builder()
                .baseUrl(emailUrl)
                .build();
        this.active = active;
    }

    public void sendEmail(EmailReq req) {
        if (!active) {
            return;
        }

        webClient.post()
                .uri("/send-email")
                .bodyValue(req)
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }

}
