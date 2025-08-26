package information.security.informationsecurity.model.certificate;

import information.security.informationsecurity.model.auth.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "certificate")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Certificate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "serial_number", unique = true, nullable = false)
    private String serialNumber;

    @Column(name = "subject_dn", nullable = false)
    private String subjectDN;

    @Column(name = "issuer_dn", nullable = false)
    private String issuerDN;

    @Column(name = "public_key", columnDefinition = "TEXT")
    private String publicKey;

    @Column(name = "certificate_data", columnDefinition = "TEXT")
    private String certificateData; // Base64 encoded certificate

    @Enumerated(EnumType.STRING)
    @Column(name = "certificate_type")
    private CertificateType certificateType;

    @Column(name = "valid_from")
    private LocalDateTime validFrom;

    @Column(name = "valid_to")
    private LocalDateTime validTo;

    @Column(name = "key_usage")
    private String keyUsage;

    @Column(name = "extended_key_usage")
    private String extendedKeyUsage;

    @Column(name = "basic_constraints")
    private String basicConstraints;

    @Column(name = "subject_alternative_names")
    private String subjectAlternativeNames;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_certificate_id")
    private Certificate issuerCertificate; // Parent CA certificate

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id")
    private User owner;

    @Column(name = "revoked")
    private boolean revoked = false;

    @Column(name = "revocation_date")
    private LocalDateTime revocationDate;

    @Enumerated(EnumType.STRING)
    @Column(name = "revocation_reason")
    private RevocationReason revocationReason;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "issuerCertificate", cascade = CascadeType.ALL)
    private List<Certificate> issuedCertificates;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}