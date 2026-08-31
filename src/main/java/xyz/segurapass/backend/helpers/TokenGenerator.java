package xyz.segurapass.backend.helpers;

public interface TokenGenerator {
    String generateRefreshToken(int byteLength);
    String generateRandomToken(int length);
    String generateTotpSecret();
}
