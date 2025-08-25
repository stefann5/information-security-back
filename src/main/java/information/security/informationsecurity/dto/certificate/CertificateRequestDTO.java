package information.security.informationsecurity.dto.certificate;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateRequestDTO {
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

    private Long issuerCertificateId; // ID of CA certificate to sign with

    private String certificateType; // ROOT_CA, INTERMEDIATE_CA, END_ENTITY

    private Integer keySize; // 2048, 3072, 4096
    private String algorithm; // RSA, EC

    private Long templateId; // Optional - use predefined template
}