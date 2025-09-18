package information.security.informationsecurity.dto.auth.password;

import information.security.informationsecurity.exceptions.PasswordValidationException;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.DigestUtils;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@AllArgsConstructor
public class PasswordValidator {

    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_LENGTH = 64;

    // Common passwords - u stvarnoj aplikaciji učitaj iz fajla ili baze
    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "password", "123456", "123456789", "12345678", "12345", "1234567",
            "admin", "password123", "qwerty", "abc123", "letmein", "monkey",
            "welcome", "login", "admin123", "iloveyou", "sunshine", "password1"
    );

    public void validatePassword(String password) {
        if (password == null) {
            throw new PasswordValidationException("Password cannot be null");
        }

        // Length validation
        if (password.length() < MIN_PASSWORD_LENGTH) {
            throw new PasswordValidationException(
                    String.format("Password must be at least %d characters long", MIN_PASSWORD_LENGTH)
            );
        }

        if (password.length() > MAX_PASSWORD_LENGTH) {
            throw new PasswordValidationException(
                    String.format("Password must not exceed %d characters", MAX_PASSWORD_LENGTH)
            );
        }

        // Check for uppercase letters
        if (!password.matches(".*[A-Z].*")) {
            throw new PasswordValidationException("Password must contain at least one uppercase letter");
        }

        // Check for numbers
        if (!password.matches(".*\\d.*")) {
            throw new PasswordValidationException("Password must contain at least one number");
        }

        // Check for special characters
        if (!password.matches(".*[!@#$%^&*()_+\\-\\=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            throw new PasswordValidationException("Password must contain at least one special character");
        }


        // Check against common passwords
        if (COMMON_PASSWORDS.contains(password.toLowerCase())) {
            throw new PasswordValidationException("Password is too common. Please choose a different password.");
        }

        // Check against pwned passwords
        if (isPwnedPassword(password)) {
            throw new PasswordValidationException("This password has been found in data breaches. Please choose a different password.");
        }
    }


    private boolean isPwnedPassword(String password) {
        try {
            // Generiši SHA-1 hash od password-a
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            String sha1Hash = bytesToHex(hashBytes).toUpperCase();

            String hashPrefix = sha1Hash.substring(0, 5);
            String hashSuffix = sha1Hash.substring(5);

            String url = "https://api.pwnedpasswords.com/range/" + hashPrefix;

            RestTemplate restTemplate = new RestTemplate();
            String response = restTemplate.getForObject(url, String.class);

            // Proveri da li se hash suffix nalazi u odgovoru
            return Arrays.stream(response.split("\n"))
                    .anyMatch(line -> line.startsWith(hashSuffix));

        } catch (Exception e) {
            // Fallback na lokalnu listu ako API ne radi
            throw new PasswordValidationException("This password has been found in data breaches. Please choose a different password.");
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
