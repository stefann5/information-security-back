package information.security.informationsecurity.dto.certificate;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AutoGenerateResponseDTO {
    private Long certificateId;
    private String serialNumber;
    private String subjectDN;
    private byte[] keystoreBytes;
    private String message;
}
