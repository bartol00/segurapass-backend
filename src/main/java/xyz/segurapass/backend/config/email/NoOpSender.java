package xyz.segurapass.backend.config.email;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import xyz.segurapass.api.email.EmailReq;

@Component
@ConditionalOnProperty(
        name = "app.email.active",
        havingValue = "false",
        matchIfMissing = true
)
public class NoOpSender implements EmailSender{

    @Override
    public void sendEmail(EmailReq req) {
        // Email functionality is disabled
    }
}
