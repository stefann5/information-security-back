package information.security.informationsecurity.dto.certificate;

import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
public class AutoGenerateCertificateDTO {
    private String commonName;
    private String organizationName;
    private String organizationalUnit;
    private String countryCode;
    private String emailAddress;
    private String locality;
    private String state;

    private Long issuerCertificateId;
    private LocalDateTime validFrom;
    private LocalDateTime validTo;

    private String algorithm = "RSA";
    private Integer keySize = 2048;

    private List<String> keyUsage;
    private List<String> extendedKeyUsage;
    private List<String> subjectAlternativeNames;

    private String keystoreType = "PKCS12";
    private String keystorePassword;
    private String alias = "certificate";
}
