package xyz.segurapass.backend.config.email;

import xyz.segurapass.api.email.EmailReq;

public interface EmailSender {
    void sendEmail(EmailReq req);
}
