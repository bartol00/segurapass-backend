package xyz.segurapass.backend.config;

import lombok.Getter;
import org.springframework.kafka.core.KafkaTemplate;
import xyz.segurapass.api.email.EmailReq;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EmailClient {

    @Getter
    private final boolean active;
    private final KafkaTemplate<String, EmailReq> kafkaTemplate;

    public static final String EMAIL_TOPIC = "segurapass-email";

    public EmailClient(
            KafkaTemplate<String, EmailReq> kafkaTemplate,
            @Value("${app.email.active}") boolean active
    ) {
        this.kafkaTemplate = kafkaTemplate;
        this.active = active;
    }

    public void sendEmail(EmailReq req) {
        if (!active) {
            return;
        }
        kafkaTemplate.send(EMAIL_TOPIC, req);
    }

}
