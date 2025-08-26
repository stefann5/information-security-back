package information.security.informationsecurity.dto.certificate;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class KeystoreDownloadDTO {
    private Long certificateId;
    private String keystorePassword;
    private String keystoreType; // PKCS12 or JKS
    private String alias;
}