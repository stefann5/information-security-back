package information.security.informationsecurity.dto.certificate;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TemplateResponseDTO {
    private Long id;
    private String templateName;
    private String caIssuerName;
    private String commonNameRegex;
    private String sanRegex;
    private Integer maxTtlDays;
    private String defaultKeyUsage;
    private String defaultExtendedKeyUsage;
    private String createdBy;
    private LocalDateTime createdAt;
}