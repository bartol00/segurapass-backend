package xyz.segurapass.backend.config.email;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import xyz.segurapass.api.email.EmailReq;
import xyz.segurapass.backend.config.KafkaConfig;

@Component
@ConditionalOnProperty(
        name = "app.email.active",
        havingValue = "true"
)
@RequiredArgsConstructor
public class KafkaEmailSender implements EmailSender {

    private final KafkaTemplate<String, EmailReq> kafkaTemplate;

    @Override
    public void sendEmail(EmailReq req) {
        kafkaTemplate.send(KafkaConfig.EMAIL_TOPIC, req);
    }
}
