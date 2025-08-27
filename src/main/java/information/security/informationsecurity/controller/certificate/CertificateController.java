package information.security.informationsecurity.controller.certificate;

import information.security.informationsecurity.dto.certificate.*;
import information.security.informationsecurity.repository.user.UserRepository;
import information.security.informationsecurity.service.certificate.CertificateService;
import information.security.informationsecurity.service.certificate.KeystoreService;
import information.security.informationsecurity.service.certificate.TemplateService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/certificates")
@RequiredArgsConstructor
@CrossOrigin
public class CertificateController {

    private final CertificateService certificateService;
    private final KeystoreService keystoreService;
    private final TemplateService templateService;
    private final UserRepository userRepository;

    /**
     * Issue a new certificate
     */
    @PostMapping("/issue")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'CA')")
    public ResponseEntity<CertificateResponseDTO> issueCertificate(
            @RequestBody CertificateRequestDTO request,
            Authentication authentication) {

        try {
            CertificateResponseDTO response = certificateService.issueCertificate(
                    request, authentication.getName());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new CertificateResponseDTO(null, null, null, null, null, null, null, false, null, null, e.getMessage(), false));
        }
    }

    /**
     * Process Certificate Signing Request
     */
    @PostMapping("/csr")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'CA','COMMON')")
    public ResponseEntity<CertificateResponseDTO> processCSR(
            @RequestBody CSRRequestDTO csrRequest,
            Authentication authentication) {

        try {
            CertificateResponseDTO response = certificateService.processCSR(
                    csrRequest, authentication.getName());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new CertificateResponseDTO(null, null, null, null, null, null, null, false, null, null, e.getMessage(), false));
        }
    }

    /**
     * Get all certificates accessible to current user
     */
    @GetMapping
    public ResponseEntity<List<CertificateListDTO>> getCertificates(Authentication authentication) {
        List<CertificateListDTO> certificates = certificateService.getCertificates(authentication.getName());
        return ResponseEntity.ok(certificates);
    }

    @GetMapping("/all")
    public ResponseEntity<List<CertificateListDTO>> getAllCertificates(Authentication authentication) {
        List<CertificateListDTO> certificates = certificateService.getAllCertificates();
        return ResponseEntity.ok(certificates);
    }

    /**
     * Get specific certificate details
     */
    @GetMapping("/{id}")
    public ResponseEntity<CertificateResponseDTO> getCertificate(
            @PathVariable Long id,
            Authentication authentication) {

        try {
            CertificateResponseDTO certificate = certificateService.getCertificate(id, authentication.getName());
            return ResponseEntity.ok(certificate);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new CertificateResponseDTO(null, null, null, null, null, null, null, false, null, null, e.getMessage(), false));
        }
    }

    /**
     * Revoke certificate
     */
    @PostMapping("/{id}/revoke")
    public ResponseEntity<String> revokeCertificate(
            @PathVariable Long id,
            @RequestBody RevocationRequestDTO request,
            Authentication authentication) {

        try {
            request.setCertificateId(id);
            certificateService.revokeCertificate(request, authentication.getName());
            return ResponseEntity.ok("Certificate revoked successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to revoke certificate: " + e.getMessage());
        }
    }

    /**
     * Download certificate as keystore (PKCS12/JKS)
     */
    @PostMapping("/{id}/keystore")
    public ResponseEntity<byte[]> downloadKeystore(
            @PathVariable Long id,
            @RequestBody KeystoreDownloadDTO request,
            Authentication authentication) {

        try {
            request.setCertificateId(id);
            byte[] keystoreBytes = keystoreService.createKeystore(request,
                    getCurrentUser(authentication));

            String filename = "certificate." + request.getKeystoreType().toLowerCase();

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + filename)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(keystoreBytes);

        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Download certificate only (no private key)
     */
    @GetMapping("/{id}/download")
    public ResponseEntity<byte[]> downloadCertificate(
            @PathVariable Long id,
            @RequestParam(defaultValue = "PKCS12") String keystoreType,
            @RequestParam(defaultValue = "certificate") String password,
            @RequestParam(defaultValue = "cert") String alias,
            Authentication authentication) {

        try {
            byte[] keystoreBytes = keystoreService.createCertificateOnlyKeystore(
                    id, password, keystoreType, alias, getCurrentUser(authentication));

            String filename = "certificate." + keystoreType.toLowerCase();

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + filename)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(keystoreBytes);

        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Get available CA certificates for signing
     */
    @GetMapping("/ca-certificates")
    public ResponseEntity<List<CertificateListDTO>> getAvailableCACertificates(Authentication authentication) {
        List<CertificateListDTO> caCertificates = certificateService.getAvailableCACertificates(authentication.getName());
        return ResponseEntity.ok(caCertificates);
    }

    /**
     * Create certificate template
     */
    @PostMapping("/templates")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'CA')")
    public ResponseEntity<TemplateResponseDTO> createTemplate(
            @RequestBody TemplateRequestDTO request,
            Authentication authentication) {

        try {
            TemplateResponseDTO template = templateService.createTemplate(request, authentication.getName());
            return ResponseEntity.ok(template);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Get available templates
     */
    @GetMapping("/templates")
    public ResponseEntity<List<TemplateResponseDTO>> getTemplates(Authentication authentication) {
        List<TemplateResponseDTO> templates = templateService.getAvailableTemplates(authentication.getName());
        return ResponseEntity.ok(templates);
    }

    /**
     * Get template details
     */
    @GetMapping("/templates/{id}")
    public ResponseEntity<TemplateResponseDTO> getTemplate(@PathVariable Long id, Authentication authentication) {
        try {
            TemplateResponseDTO template = templateService.getTemplate(id, authentication.getName());
            return ResponseEntity.ok(template);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Create truststore with multiple CA certificates
     */
    @PostMapping("/truststore")
    public ResponseEntity<byte[]> createTruststore(
            @RequestBody List<Long> certificateIds,
            @RequestParam(defaultValue = "PKCS12") String keystoreType,
            @RequestParam(defaultValue = "truststore") String password,
            Authentication authentication) {

        try {
            byte[] truststoreBytes = keystoreService.createTruststore(
                    certificateIds, password, keystoreType, getCurrentUser(authentication));

            String filename = "truststore." + keystoreType.toLowerCase();

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + filename)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(truststoreBytes);

        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    // Helper methods
    private information.security.informationsecurity.model.auth.User getCurrentUser(Authentication authentication) {
        return userRepository.findByUsername(authentication.getName()).orElse(null);
    }
}