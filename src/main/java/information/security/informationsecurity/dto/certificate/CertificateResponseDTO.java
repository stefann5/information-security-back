package information.security.informationsecurity.dto.certificate;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateResponseDTO {
    private Long id;
    private String serialNumber;
    private String subjectDN;
    private String issuerDN;
    private String certificateType;
    private LocalDateTime validFrom;
    private LocalDateTime validTo;
    private boolean revoked;
    private LocalDateTime revocationDate;
    private String revocationReason;
    private String certificateData; // Base64 PEM certificate
    private boolean hasPrivateKey;
}