package information.security.informationsecurity.service.certificate;

import information.security.informationsecurity.dto.certificate.*;
import information.security.informationsecurity.model.certificate.*;
import information.security.informationsecurity.model.auth.User;
import information.security.informationsecurity.model.certificate.Certificate;
import information.security.informationsecurity.model.certificate.PrivateKey;
import information.security.informationsecurity.repository.certificate.CertificateRepository;
import information.security.informationsecurity.repository.certificate.PrivateKeyRepository;
import information.security.informationsecurity.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class CertificateService {

    private final CertificateRepository certificateRepository;
    private final PrivateKeyRepository privateKeyRepository;
    private final UserRepository userRepository;
    private final CryptographyService cryptographyService;
    private final ValidationService validationService;

    /**
     * Issue a new certificate based on the request
     */
    @PreAuthorize("hasAnyAuthority('ADMIN', 'CA')")
    public CertificateResponseDTO issueCertificate(CertificateRequestDTO request, String currentUsername) {
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Validate request
        validationService.validateCertificateRequest(request, currentUser);

        try {
            // Generate key pair
            KeyPair keyPair = cryptographyService.generateKeyPair(
                    request.getAlgorithm(), request.getKeySize());

            // Get issuer certificate for signing
            Certificate issuerCert = null;
            java.security.PrivateKey signingKey = null;

            if (!"ROOT_CA".equals(request.getCertificateType())) {
                issuerCert = certificateRepository.findById(request.getIssuerCertificateId())
                        .orElseThrow(() -> new RuntimeException("Issuer certificate not found"));

                // Validate that user can use this CA certificate
                validationService.validateCACertificateAccess(issuerCert, currentUser);

                // Get signing private key
                signingKey = cryptographyService.getDecryptedPrivateKey(issuerCert);
            }

            if (currentUser.getAuthorities().contains("CA")){
                if(!request.getOrganizationName().equals(currentUser.getOrganization())){
                    throw new RuntimeException("CA user can only issue certificates for his organization");
                }
            }

            // Create X.509 certificate
            X509Certificate x509Cert = cryptographyService.createX509Certificate(
                    request, keyPair, issuerCert, signingKey);

            // Convert to our Certificate entity
            Certificate certificate = createCertificateEntity(request, x509Cert, keyPair, issuerCert, currentUser);

            // Save certificate
            certificate = certificateRepository.save(certificate);

            // Save encrypted private key
            cryptographyService.saveEncryptedPrivateKey(certificate, keyPair.getPrivate(), currentUser);

            return convertToResponseDTO(certificate);

        } catch (Exception e) {
            throw new RuntimeException("Failed to issue certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Process Certificate Signing Request (CSR)
     */
    @PreAuthorize("hasAnyAuthority('ADMIN', 'CA','COMMON')")
    public CertificateResponseDTO processCSR(CSRRequestDTO csrRequest, String currentUsername) {
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        try {
            // Parse CSR
            var csr = cryptographyService.parseCSR(csrRequest.getCsrData());

            // Get issuer certificate
            Certificate issuerCert = certificateRepository.findById(csrRequest.getIssuerCertificateId())
                    .orElseThrow(() -> new RuntimeException("Issuer certificate not found"));

            validationService.validateCACertificateAccess(issuerCert, currentUser);

            // Get signing private key
            java.security.PrivateKey signingKey = cryptographyService.getDecryptedPrivateKey(issuerCert);

            // Create certificate from CSR
            X509Certificate x509Cert = cryptographyService.createCertificateFromCSR(
                    csr, issuerCert, signingKey, csrRequest.getValidityDays());

            // Create certificate entity (without private key since it's external CSR)
            Certificate certificate = createCertificateFromCSR(x509Cert, issuerCert, currentUser);
            certificate = certificateRepository.save(certificate);

            return convertToResponseDTO(certificate);

        } catch (Exception e) {
            throw new RuntimeException("Failed to process CSR: " + e.getMessage(), e);
        }
    }

    /**
     * Get certificates accessible to current user
     */
    public List<CertificateListDTO> getCertificates(String currentUsername) {
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<Certificate> certificates;

        if (currentUser.getAuthorities().contains("ADMIN")) {
            // Admin can see all certificates
            certificates = certificateRepository.findAll();
        } else if (currentUser.getAuthorities().contains("CA")) {
            // CA user can see certificates in their chain
            certificates = getCertificatesInUserChain(currentUser);
        } else {
            // Regular user can see only their certificates
            certificates = certificateRepository.findByOwnerAndRevokedFalse(currentUser);
        }

        return certificates.stream()
                .map(this::convertToListDTO)
                .collect(Collectors.toList());
    }

    public List<CertificateListDTO> getAllCertificates() {
        List<Certificate> certificates = certificateRepository.findByRevokedFalse();
        return certificates.stream()
                .map(this::convertToListDTO)
                .collect(Collectors.toList());
    }

    /**
     * Get certificate details
     */
    public CertificateResponseDTO getCertificate(Long certificateId, String currentUsername) {
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Certificate certificate = certificateRepository.findById(certificateId)
                .orElseThrow(() -> new RuntimeException("Certificate not found"));

        // Check access rights
        validationService.validateCertificateAccess(certificate, currentUser);

        return convertToResponseDTO(certificate);
    }

    /**
     * Revoke certificate
     */
    @PreAuthorize("hasAnyAuthority('ADMIN', 'CA', 'COMMON')")
    public void revokeCertificate(RevocationRequestDTO request, String currentUsername) {
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Certificate certificate = certificateRepository.findById(request.getCertificateId())
                .orElseThrow(() -> new RuntimeException("Certificate not found"));

        // Validate revocation rights
        validationService.validateRevocationRights(certificate, currentUser);

        certificate.setRevoked(true);
        certificate.setRevocationDate(LocalDateTime.now());
        certificate.setRevocationReason(RevocationReason.valueOf(request.getRevocationReason()));

        certificateRepository.save(certificate);
    }

    /**
     * Get available CA certificates for signing
     */
    public List<CertificateListDTO> getAvailableCACertificates(String currentUsername) {
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<Certificate> caCertificates;

        if (currentUser.getAuthorities().contains("ADMIN")) {
            caCertificates = certificateRepository.findValidCACertificates(LocalDateTime.now());
        } else {
            caCertificates = certificateRepository.findCACertificatesByOwner(currentUser);
        }

        return caCertificates.stream()
                .map(this::convertToListDTO)
                .collect(Collectors.toList());
    }

    // Helper methods

    private Certificate createCertificateEntity(CertificateRequestDTO request, X509Certificate x509Cert,
                                                KeyPair keyPair, Certificate issuerCert, User owner) {
        Certificate certificate = new Certificate();

        certificate.setSerialNumber(x509Cert.getSerialNumber().toString());
        certificate.setSubjectDN(x509Cert.getSubjectDN().toString());
        certificate.setIssuerDN(x509Cert.getIssuerDN().toString());
        certificate.setCertificateType(CertificateType.valueOf(request.getCertificateType()));
        certificate.setValidFrom(LocalDateTime.ofInstant(x509Cert.getNotBefore().toInstant(), ZoneId.systemDefault()));
        certificate.setValidTo(LocalDateTime.ofInstant(x509Cert.getNotAfter().toInstant(), ZoneId.systemDefault()));
        certificate.setOwner(owner);
        certificate.setIssuerCertificate(issuerCert);

        // Store certificate data as Base64 PEM
        try {
            certificate.setCertificateData(cryptographyService.certificateToPEM(x509Cert));
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert certificate to PEM", e);
        }

        // Set extensions
        if (request.getKeyUsage() != null) {
            certificate.setKeyUsage(String.join(",", request.getKeyUsage()));
        }
        if (request.getExtendedKeyUsage() != null) {
            certificate.setExtendedKeyUsage(String.join(",", request.getExtendedKeyUsage()));
        }
        if (request.getSubjectAlternativeNames() != null) {
            certificate.setSubjectAlternativeNames(String.join(",", request.getSubjectAlternativeNames()));
        }

        return certificate;
    }

    private Certificate createCertificateFromCSR(X509Certificate x509Cert, Certificate issuerCert, User owner) {
        Certificate certificate = new Certificate();

        certificate.setSerialNumber(x509Cert.getSerialNumber().toString());
        certificate.setSubjectDN(x509Cert.getSubjectDN().toString());
        certificate.setIssuerDN(x509Cert.getIssuerDN().toString());
        certificate.setCertificateType(CertificateType.END_ENTITY); // CSR is typically for end-entity
        certificate.setValidFrom(LocalDateTime.ofInstant(x509Cert.getNotBefore().toInstant(), ZoneId.systemDefault()));
        certificate.setValidTo(LocalDateTime.ofInstant(x509Cert.getNotAfter().toInstant(), ZoneId.systemDefault()));
        certificate.setOwner(owner);
        certificate.setIssuerCertificate(issuerCert);

        try {
            certificate.setCertificateData(cryptographyService.certificateToPEM(x509Cert));
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert certificate to PEM", e);
        }

        return certificate;
    }

    private List<Certificate> getCertificatesInUserChain(User caUser) {
        // Get all CA certificates owned by user
        List<Certificate> userCACerts = certificateRepository.findCACertificatesByOwner(caUser);

        Set<Certificate> allCerts = new HashSet<>(userCACerts);

        // Add all certificates issued by user's CA certificates
        for (Certificate caCert : userCACerts) {
            allCerts.addAll(certificateRepository.findByIssuerCertificateAndRevokedFalse(caCert));
        }

        return new ArrayList<>(allCerts);
    }

    private CertificateResponseDTO convertToResponseDTO(Certificate certificate) {
        CertificateResponseDTO dto = new CertificateResponseDTO();
        dto.setId(certificate.getId());
        dto.setSerialNumber(certificate.getSerialNumber());
        dto.setSubjectDN(certificate.getSubjectDN());
        dto.setIssuerDN(certificate.getIssuerDN());
        dto.setCertificateType(certificate.getCertificateType().toString());
        dto.setValidFrom(certificate.getValidFrom());
        dto.setValidTo(certificate.getValidTo());
        dto.setRevoked(certificate.isRevoked());
        dto.setRevocationDate(certificate.getRevocationDate());
        dto.setRevocationReason(certificate.getRevocationReason() != null ?
                certificate.getRevocationReason().toString() : null);
        dto.setCertificateData(certificate.getCertificateData());
        dto.setHasPrivateKey(privateKeyRepository.existsByCertificate(certificate));

        return dto;
    }

    private CertificateListDTO convertToListDTO(Certificate certificate) {
        CertificateListDTO dto = new CertificateListDTO();
        dto.setId(certificate.getId());
        dto.setSerialNumber(certificate.getSerialNumber());
        dto.setSubjectDN(certificate.getSubjectDN());
        dto.setCertificateType(certificate.getCertificateType().toString());
        dto.setValidFrom(certificate.getValidFrom());
        dto.setValidTo(certificate.getValidTo());
        dto.setRevoked(certificate.isRevoked());

        // Extract CN from subject DN
        String cn = extractCNFromDN(certificate.getSubjectDN());
        dto.setCommonName(cn);

        // Get issuer CN
        if (certificate.getIssuerCertificate() != null) {
            String issuerCN = extractCNFromDN(certificate.getIssuerCertificate().getSubjectDN());
            dto.setIssuerCommonName(issuerCN);
        } else {
            dto.setIssuerCommonName("Self-signed");
        }

        return dto;
    }

    private String extractCNFromDN(String dn) {
        if (dn == null) return "";

        String[] parts = dn.split(",");
        for (String part : parts) {
            if (part.trim().toUpperCase().startsWith("CN=")) {
                return part.trim().substring(3);
            }
        }
        return "";
    }

    /**
     * Issue a new certificate for a specific user (used by admin)
     */
    @PreAuthorize("hasAnyAuthority('ADMIN', 'CA')")
    public CertificateResponseDTO issueCertificateForUser(CertificateRequestDTO request, String currentUsername, User targetUser) {
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Validate request
        validationService.validateCertificateRequest(request, currentUser);

        try {
            // Generate key pair
            KeyPair keyPair = cryptographyService.generateKeyPair(
                    request.getAlgorithm(), request.getKeySize());

            // Get issuer certificate for signing
            Certificate issuerCert = null;
            java.security.PrivateKey signingKey = null;

            if (!"ROOT_CA".equals(request.getCertificateType())) {
                issuerCert = certificateRepository.findById(request.getIssuerCertificateId())
                        .orElseThrow(() -> new RuntimeException("Issuer certificate not found"));

                // Validate that user can use this CA certificate
                validationService.validateCACertificateAccess(issuerCert, currentUser);

                // Get signing private key
                signingKey = cryptographyService.getDecryptedPrivateKey(issuerCert);
            }

            // Create X.509 certificate
            X509Certificate x509Cert = cryptographyService.createX509Certificate(
                    request, keyPair, issuerCert, signingKey);

            // Convert to our Certificate entity - assign ownership to target user
            Certificate certificate = createCertificateEntity(request, x509Cert, keyPair, issuerCert, targetUser);

            // Save certificate
            certificate = certificateRepository.save(certificate);

            // Save encrypted private key for target user
            cryptographyService.saveEncryptedPrivateKey(certificate, keyPair.getPrivate(), targetUser);

            return convertToResponseDTO(certificate);

        } catch (Exception e) {
            throw new RuntimeException("Failed to issue certificate: " + e.getMessage(), e);
        }
    }
}