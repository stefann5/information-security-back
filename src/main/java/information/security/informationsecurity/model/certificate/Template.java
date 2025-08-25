package information.security.informationsecurity.model.certificate;

import information.security.informationsecurity.model.auth.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "certificate_template")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Template {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "template_name", nullable = false)
    private String templateName;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ca_issuer_id")
    private Certificate caIssuer;

    @Column(name = "common_name_regex")
    private String commonNameRegex;

    @Column(name = "san_regex")
    private String sanRegex;

    @Column(name = "max_ttl_days")
    private Integer maxTtlDays;

    @Column(name = "default_key_usage")
    private String defaultKeyUsage;

    @Column(name = "default_extended_key_usage")
    private String defaultExtendedKeyUsage;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private User createdBy;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}