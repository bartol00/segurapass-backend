package com.security.passwordmanager.helpers.impl;

import com.security.passwordmanager.api.email.EmailReq;
import com.security.passwordmanager.config.EmailClient;
import com.security.passwordmanager.helpers.EmailService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.ses.model.*;

@Component
public class EmailServiceImpl implements EmailService {

    private final EmailClient emailClient;

    @Value("${app.base.url}")
    private String baseUrl;

    public EmailServiceImpl(EmailClient emailClient) {
        this.emailClient = emailClient;
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
            EmailReq emailReq = new EmailReq();
            emailReq.setTo(to);
            emailReq.setSubject(subject);
            emailReq.setText(textBody);
            emailReq.setHtml(htmlBody);

            emailClient.sendEmail(emailReq);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendDeletionEmail(String to, String verificationToken) {
        String subject = "Delete your SeguraPass account";
        String verificationLink = baseUrl + "/api/deletion/email/end/" + verificationToken;

        String textBody = String.format(
                "Welcome to SeguraPass!\n\nClick the link below to verify your account:\n%s\n\nIf you didn’t request this, you can ignore it.\n\nThe verification link expires 15 minutes from now.",
                verificationLink
        );

        String htmlBody = String.format("""
            <html>
                <body style="font-family: Arial, sans-serif;">
                    <h2>We're sorry to see you go!</h2>
                    <p>Click below to send an account deletion request:</p>
                    <p><a href="%s">Delete Your Account</a></p>
                    <p>If you didn’t request this, please ignore it.</p>
                    <p>The deletion link expires 15 minutes from now.</p>
                </body>
            </html>
        """, verificationLink);

        try {
            EmailReq emailReq = new EmailReq();
            emailReq.setTo(to);
            emailReq.setSubject(subject);
            emailReq.setText(textBody);
            emailReq.setHtml(htmlBody);

            emailClient.sendEmail(emailReq);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
