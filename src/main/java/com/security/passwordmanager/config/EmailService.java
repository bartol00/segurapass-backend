package com.security.passwordmanager.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.ses.SesClient;
import software.amazon.awssdk.services.ses.model.*;

@Component
public class EmailService {

    private final SesClient sesClient;

    @Value("${aws.fromEmail}")
    private String fromEmail;

    @Value("${app.base.url}")
    private String baseUrl;

    public EmailService(SesClient sesClient) {
        this.sesClient = sesClient;
    }

    public void sendVerificationEmail(String to, String verificationToken) {
        String subject = "Verify your SeguraPass account";
        String verificationLink = baseUrl + "/api/authorization/verify/" + verificationToken;

        String textBody = String.format(
                "Welcome to SeguraPass!\n\nClick the link below to verify your account:\n%s\n\nIf you didn’t request this, you can ignore it.\n\nThe verification link expires 15 minutes from now.",
                verificationLink
        );

        String htmlBody = String.format("""
            <html>
                <body style="font-family: Arial, sans-serif;">
                    <h2>Welcome to SeguraPass!</h2>
                    <p>Click below to verify your email:</p>
                    <p><a href="%s">Verify Email</a></p>
                    <p>If you didn’t request this, please ignore it.</p>
                    <p>The verification link expires 15 minutes from now.</p>
                </body>
            </html>
        """, verificationLink);

        try {
            SendEmailRequest emailRequest = SendEmailRequest.builder()
                    .source(fromEmail)
                    .destination(Destination.builder().toAddresses(to).build())
                    .message(Message.builder()
                            .subject(Content.builder().data(subject).charset("UTF-8").build())
                            .body(Body.builder()
                                    .html(Content.builder().data(htmlBody).charset("UTF-8").build())
                                    .text(Content.builder().data(textBody).charset("UTF-8").build())
                                    .build())
                            .build())
                    .build();

            sesClient.sendEmail(emailRequest);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
