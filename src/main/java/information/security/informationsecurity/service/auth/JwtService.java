package information.security.informationsecurity.service.auth;

import information.security.informationsecurity.exceptions.TokenExpiredException;
import information.security.informationsecurity.repository.auth.TokenRepository;
import information.security.informationsecurity.repository.user.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Optional;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.access-token-expiration}")
    private long accessTokenExpire;

    @Value("${application.security.jwt.refresh-token-expiration}")
    private long refreshTokenExpire;

    @Value("${application.front.address.login}")
    private String frontLoginAddress;

    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;


    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }


    public boolean isValid(String token, UserDetails user) {
        String username = extractUsername(token);

        boolean validToken = tokenRepository
                .findByAccessToken(token)
                .map(t -> !t.isLoggedOut())
                .orElse(false);

        return (username.equals(user.getUsername())) && !isTokenExpired(token) && validToken;
    }

    public boolean isValidRefreshToken(String token, information.security.informationsecurity.model.auth.User user) {
        String username = extractUsername(token);

        try{
            boolean validRefreshToken = tokenRepository
                    .findByRefreshToken(token)
                    .map(t -> !t.isLoggedOut())
                    .orElse(false);

            return (username.equals(user.getUsername())) && !isTokenExpired(token) && validRefreshToken;
        }catch (ExpiredJwtException e){
            throw new TokenExpiredException("Token expired");
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSigninKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


    public String generateAccessToken(information.security.informationsecurity.model.auth.User user) {
        return generateToken(user, accessTokenExpire);
    }

    public String generateRefreshToken(information.security.informationsecurity.model.auth.User user) {
        return generateToken(user, refreshTokenExpire);
    }

    private String generateToken(information.security.informationsecurity.model.auth.User user, long expireTime) {
        String token = Jwts
                .builder()
                .subject(user.getUsername())
                .claim("id", user.getId())
                .claim("role", user.getRole())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expireTime))
                .signWith(getSigninKey())
                .compact();

        return token;
    }

    private SecretKey getSigninKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateActivationToken(User user, long activationTokenExpire) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + activationTokenExpire))
                .signWith(getSigninKey())
                .compact();
    }
}
