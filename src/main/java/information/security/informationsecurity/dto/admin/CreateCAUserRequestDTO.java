package information.security.informationsecurity.dto.admin;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateCAUserRequestDTO {
    private String username;
    private String password;
    private String name;
    private String surname;
    private String organization;
}