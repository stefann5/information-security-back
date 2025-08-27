package information.security.informationsecurity.service.certificate;

import information.security.informationsecurity.dto.certificate.CertificateRequestDTO;
import information.security.informationsecurity.model.certificate.Certificate;
import information.security.informationsecurity.model.certificate.CertificateType;
import information.security.informationsecurity.model.auth.User;
import information.security.informationsecurity.repository.certificate.CertificateRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class ValidationService {

    private final CertificateRepository certificateRepository;

    /**
     * Validate certificate request
     */
    public void validateCertificateRequest(CertificateRequestDTO request, User currentUser) {
        // Basic validations
        if (request.getCommonName() == null || request.getCommonName().trim().isEmpty()) {
            throw new RuntimeException("Common Name is required");
        }

        if (request.getValidFrom() == null || request.getValidTo() == null) {
            throw new RuntimeException("Validity dates are required");
        }

        if (request.getValidFrom().isAfter(request.getValidTo())) {
            throw new RuntimeException("Valid from date must be before valid to date");
        }

        // Validate certificate type permissions
        validateCertificateTypePermissions(request.getCertificateType(), currentUser);

        // Validate issuer certificate if not root CA
        if (!"ROOT_CA".equals(request.getCertificateType())) {
            if (request.getIssuerCertificateId() == null) {
                throw new RuntimeException("Issuer certificate is required for non-root certificates");
            }
        }

        // Check for duplicate subject DN
        String subjectDN = buildSubjectDN(request);
        if (certificateRepository.existsBySubjectDNAndRevokedFalse(subjectDN)) {
            throw new RuntimeException("Certificate with this subject already exists");
        }
    }

    /**
     * Validate that user can use the specified CA certificate
     */
    public void validateCACertificateAccess(Certificate caCertificate, User currentUser) {
        // Admin can use any CA certificate
        if (currentUser.getAuthorities().contains("ADMIN")) {
            return;
        }

        // CA user can only use their own certificates
        if (currentUser.getAuthorities().contains("CA")) {
            if (!((caCertificate.getOwner().getId())==(currentUser.getId()))) {
                throw new RuntimeException("You can only use your own CA certificates");
            }
        }

        // Validate CA certificate is still valid
        if (caCertificate.isRevoked()) {
            throw new RuntimeException("CA certificate is revoked");
        }

        if (caCertificate.getValidTo().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("CA certificate has expired");
        }

        // Check if it's actually a CA certificate
        if (caCertificate.getCertificateType() != CertificateType.ROOT_CA &&
                caCertificate.getCertificateType() != CertificateType.INTERMEDIATE_CA) {
            throw new RuntimeException("Certificate is not a CA certificate");
        }
    }

    /**
     * Validate certificate access rights
     */
    public void validateCertificateAccess(Certificate certificate, User currentUser) {
        if (currentUser.getAuthorities().contains("ADMIN")) {
            return; // Admin can access all certificates
        }

        if (currentUser.getAuthorities().contains("CA")) {
            // CA user can access certificates in their chain
            if (isCertificateInUserChain(certificate, currentUser)) {
                return;
            }
        }

        // Regular users can only access their own certificates
        if (certificate.getOwner().getId()==(currentUser.getId())) {
            return;
        }

        throw new RuntimeException("You don't have permission to access this certificate");
    }

    /**
     * Validate revocation rights
     */
    public void validateRevocationRights(Certificate certificate, User currentUser) {
        // Users can revoke their own certificates
        if (certificate.getOwner().getId()==(currentUser.getId())) {
            return;
        }

        // CA users can revoke certificates they issued
        if (currentUser.getAuthorities().contains("CA")) {
            if (certificate.getIssuerCertificate() != null &&
                    certificate.getIssuerCertificate().getOwner().getId()==(currentUser.getId())) {
                return;
            }
        }

        // Admin can revoke any certificate
        if (currentUser.getAuthorities().contains("ADMIN")) {
            return;
        }

        throw new RuntimeException("You don't have permission to revoke this certificate");
    }

    /**
     * Validate template CN regex against certificate CN
     */
    public boolean validateCNAgainstTemplate(String cn, String cnRegex) {
        if (cnRegex == null || cnRegex.trim().isEmpty()) {
            return true; // No restriction
        }

        try {
            return Pattern.matches(cnRegex, cn);
        } catch (Exception e) {
            return false;
        }
    }

    // Private helper methods

    private void validateCertificateTypePermissions(String certificateType, User currentUser) {
        if ("ROOT_CA".equals(certificateType) && !currentUser.getAuthorities().contains("ADMIN")) {
            throw new RuntimeException("Only administrators can create root CA certificates");
        }

        if ("INTERMEDIATE_CA".equals(certificateType) &&
                !currentUser.getAuthorities().contains("ADMIN") &&
                !currentUser.getAuthorities().contains("CA")) {
            throw new RuntimeException("Only administrators and CA users can create intermediate CA certificates");
        }
    }

    private String buildSubjectDN(CertificateRequestDTO request) {
        StringBuilder dn = new StringBuilder();
        dn.append("CN=").append(request.getCommonName());

        if (request.getOrganizationName() != null) {
            dn.append(",O=").append(request.getOrganizationName());
        }
        if (request.getOrganizationalUnit() != null) {
            dn.append(",OU=").append(request.getOrganizationalUnit());
        }
        if (request.getCountryCode() != null) {
            dn.append(",C=").append(request.getCountryCode());
        }
        if (request.getEmailAddress() != null) {
            dn.append(",E=").append(request.getEmailAddress());
        }
        if(request.getLocality() != null) {
            dn.append(",L=").append(request.getLocality());
        }
        if(request.getState() != null) {
            dn.append(",ST=").append(request.getState());
        }

        return dn.toString();
    }

    private boolean isCertificateInUserChain(Certificate certificate, User caUser) {
        // Check if certificate is issued by any of user's CA certificates
        Certificate issuer = certificate.getIssuerCertificate();
        while (issuer != null) {
            if (issuer.getOwner().getId()==(caUser.getId())) {
                return true;
            }
            issuer = issuer.getIssuerCertificate();
        }
        return false;
    }
}