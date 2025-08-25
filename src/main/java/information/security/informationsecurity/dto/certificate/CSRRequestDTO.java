package information.security.informationsecurity.dto.certificate;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CSRRequestDTO {
    private String csrData; // PEM encoded CSR
    private Long issuerCertificateId; // CA to sign the CSR
    private Integer validityDays;
    private Long templateId; // Optional template
}