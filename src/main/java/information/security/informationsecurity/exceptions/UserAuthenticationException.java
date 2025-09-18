package information.security.informationsecurity.exceptions;

import lombok.Getter;

public class UserAuthenticationException extends RuntimeException {

    public enum ErrorType {
        USER_NOT_FOUND,
        INVALID_CREDENTIALS,
        USER_NOT_ACTIVE
    }

    @Getter
    private final ErrorType errorType;

    public UserAuthenticationException(String message, ErrorType errorType) {
        super(message);
        this.errorType = errorType;
    }
}