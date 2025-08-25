package information.security.informationsecurity.dto.certificate;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RevocationRequestDTO {
    private Long certificateId;
    private String revocationReason;
    private String reasonText;
}