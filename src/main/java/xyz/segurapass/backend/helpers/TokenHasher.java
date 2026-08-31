package xyz.segurapass.backend.helpers;

public interface TokenHasher {
    String generateSha256(String input);
    String generateSha256Email(String email);
}
