package information.security.informationsecurity.dto.certificate;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TemplateRequestDTO {
    private String templateName;
    private Long caIssuerId;
    private String commonNameRegex;
    private String sanRegex;
    private Integer maxTtlDays;
    private String defaultKeyUsage;
    private String defaultExtendedKeyUsage;
}
