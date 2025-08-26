package information.security.informationsecurity.dto.auth;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthenticationResponse {
    private String accessToken;

    private String refreshToken;

    private String message;

    public AuthenticationResponse(String accessToken, String refreshToken, String message) {
        this.accessToken = accessToken;
        this.message = message;
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getMessage() {
        return message;
    }
}
