package information.security.informationsecurity.dto.certificate;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateListDTO {
    private Long id;
    private String serialNumber;
    private String commonName;
    private String subjectDN;
    private String certificateType;
    private LocalDateTime validFrom;
    private LocalDateTime validTo;
    private boolean revoked;
    private String issuerCommonName;
}