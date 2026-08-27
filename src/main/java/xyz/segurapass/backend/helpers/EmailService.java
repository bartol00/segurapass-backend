package xyz.segurapass.backend.helpers;

public interface EmailService {
    void sendVerificationEmail(String to, String verificationToken);
    void sendDeletionEmail(String to, String verificationToken);
}
