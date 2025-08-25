package information.security.informationsecurity.model.certificate;

public enum CertificateType {
    ROOT_CA,        // Self-signed root certificate
    INTERMEDIATE_CA, // Intermediate CA certificate
    END_ENTITY      // End-entity certificate
}
