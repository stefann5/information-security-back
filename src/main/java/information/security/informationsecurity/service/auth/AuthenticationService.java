package information.security.informationsecurity.service.auth;

import information.security.informationsecurity.dto.auth.AuthenticationResponse;
import information.security.informationsecurity.dto.auth.LoginRequestDTO;
import information.security.informationsecurity.dto.auth.LoginResponseDTO;
import information.security.informationsecurity.exceptions.UserAuthenticationException;
import information.security.informationsecurity.model.auth.Token;
import information.security.informationsecurity.model.auth.User;
import information.security.informationsecurity.repository.auth.TokenRepository;
import information.security.informationsecurity.repository.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final information.security.informationsecurity.repository.auth.TokenRepository tokenRepository;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    private String generateSecurePassword() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public LoginResponseDTO authenticate(LoginRequestDTO request) {
        // Lookup user by email
        User user = repository.findByUsername(request.getEmail())
                .orElseThrow(() -> new UserAuthenticationException(
                        "Invalid email or password",
                        UserAuthenticationException.ErrorType.USER_NOT_FOUND
                ));


        // Authenticate user credentials
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.getEmail(),
                    request.getPassword()
            ));
        } catch (Exception e) {
            throw new UserAuthenticationException(
                    "Invalid email or password",
                    UserAuthenticationException.ErrorType.INVALID_CREDENTIALS
            );
        }

        // Generate tokens for the user
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        // Revoke any previous tokens
        revokeAllTokenByUser(user);

        // Save new tokens
        saveUserToken(accessToken, refreshToken, user);

        return new LoginResponseDTO(accessToken, refreshToken);
    }

    private void revokeAllTokenByUser(User user) {
        List<information.security.informationsecurity.model.auth.Token> validTokens = tokenRepository.findAllAccessTokensByUser(user.getId());
        if(validTokens.isEmpty()) {
            return;
        }  

        validTokens.forEach(t-> {
            t.setLoggedOut(true);
        });

        tokenRepository.saveAll(validTokens);
    }
    private void saveUserToken(String accessToken, String refreshToken, User user) {
        information.security.informationsecurity.model.auth.Token token = new information.security.informationsecurity.model.auth.Token();
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setLoggedOut(false);
        token.setUser(user);
        tokenRepository.save(token);
    }

    public ResponseEntity<AuthenticationResponse> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) {

        // Extract the token from the Authorization header
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);

        // Extract username from the token
        String username = jwtService.extractUsername(token);

        // Check if the user exists in the database
        User user = repository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("No user found"));

        // Check if the token is valid
        if (jwtService.isValidRefreshToken(token, user)) {
            // Generate new access and refresh tokens
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            // Revoke all previous tokens and save the new ones
            revokeAllTokenByUser(user);
            saveUserToken(accessToken, refreshToken, user);

            // Return both tokens in the response
            return ResponseEntity.ok(new AuthenticationResponse(accessToken, refreshToken, "New token generated"));
        }

        // If token is invalid or expired, return 401 Unauthorized
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }
}
