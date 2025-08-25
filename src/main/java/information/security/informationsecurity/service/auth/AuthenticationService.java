package information.security.informationsecurity.service.auth;

import information.security.informationsecurity.dto.auth.*;
import information.security.informationsecurity.exceptions.UserAuthenticationException;
import information.security.informationsecurity.model.auth.CommonUser;
import information.security.informationsecurity.model.auth.Role;
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

    public RegisterResponseDTO register(RegisterRequestDTO request) {
        if(repository.findByUsername(request.getUsername()).isPresent()) {
            return new RegisterResponseDTO(-1, "User Already Exists", null,null, null, null, null, null);
        }

        CommonUser user = new CommonUser();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setName(request.getName());
        user.setSurname(request.getSurname());
        user.setOrganization(request.getOrganization());
        user.setRole(Role.C);
        user.setAuthorities("COMMON");

        user = repository.save(user);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        saveUserToken(accessToken, refreshToken, user);

        return new RegisterResponseDTO(user.getId(), "User Created Successfully", user.getUsername(), user.getName(), user.getSurname(),request.getOrganization(), accessToken, refreshToken);

    }

    public LoginResponseDTO authenticate(LoginRequestDTO request) {
        // Lookup user by email
        User user = repository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UserAuthenticationException(
                        "Invalid email or password",
                        UserAuthenticationException.ErrorType.USER_NOT_FOUND
                ));


        // Authenticate user credentials
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
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

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthenticationResponse(null, null, "Missing or invalid Authorization header"));
        }

        String token = authHeader.substring(7);

        try {
            String username = jwtService.extractUsername(token);

            User user = repository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (jwtService.isValidRefreshToken(token, user)) {
                String accessToken = jwtService.generateAccessToken(user);
                String refreshToken = jwtService.generateRefreshToken(user);

                revokeAllTokenByUser(user);
                saveUserToken(accessToken, refreshToken, user);

                return ResponseEntity.ok(new AuthenticationResponse(accessToken, refreshToken, "Tokens refreshed successfully"));
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthenticationResponse(null, null, "Invalid refresh token"));

        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthenticationResponse(null, null, "Refresh token expired"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthenticationResponse(null, null, "Token refresh failed"));
        }
    }
}
