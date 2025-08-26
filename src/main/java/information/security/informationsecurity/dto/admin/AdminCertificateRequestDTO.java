package information.security.informationsecurity.dto.admin;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AdminCertificateRequestDTO {
    private Integer caUserId; // ID of CA user for whom to issue certificate
    private String commonName;
    private String organizationName;
    private String organizationalUnit;
    private String countryCode;
    private String emailAddress;
    private String locality;
    private String state;

    private List<String> subjectAlternativeNames;

    private LocalDateTime validFrom;
    private LocalDateTime validTo;

    private List<String> keyUsage;
    private List<String> extendedKeyUsage;

    private Boolean isCA;
    private Integer pathLenConstraint;

    private Long issuerCertificateId; // Parent CA certificate (for intermediate CA)

    private String certificateType; // ROOT_CA, INTERMEDIATE_CA

    private Integer keySize;
    private String algorithm;

    private String description; // Additional info about the certificate purpose
}