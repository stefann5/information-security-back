package information.security.informationsecurity.dto.admin;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CAUserResponseDTO {
    private Integer id;
    private String username;
    private String name;
    private String surname;
    private String organization;
    private boolean active;
    private LocalDateTime createdAt;
    private int certificateCount; // Number of certificates owned by this CA user
}