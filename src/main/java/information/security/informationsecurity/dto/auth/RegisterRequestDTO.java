package information.security.informationsecurity.dto.auth;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class RegisterRequestDTO {
    private String username;
    private String password;
    private String name;
    private String surname;
    private String organization;
}
