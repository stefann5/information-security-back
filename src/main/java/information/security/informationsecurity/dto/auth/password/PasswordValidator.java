package information.security.informationsecurity.dto.auth.password;

import information.security.informationsecurity.exceptions.PasswordValidationException;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Set;

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

    // Za testiranje - u produkciji koristi pravi Pwned Passwords API
    private static final Set<String> PWNED_PASSWORDS = Set.of(
            "password", "123456", "qwerty", "admin", "letmein"
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
        // U stvarnoj implementaciji pozovi Pwned Passwords API
        // https://haveibeenpwned.com/API/v3#PwnedPasswords
        return PWNED_PASSWORDS.contains(password.toLowerCase());
    }
}
