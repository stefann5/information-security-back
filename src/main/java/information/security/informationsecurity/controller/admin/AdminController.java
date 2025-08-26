package information.security.informationsecurity.controller.admin;

import information.security.informationsecurity.dto.admin.AdminCertificateRequestDTO;
import information.security.informationsecurity.dto.admin.CAUserResponseDTO;
import information.security.informationsecurity.dto.admin.CreateCAUserRequestDTO;
import information.security.informationsecurity.dto.certificate.CertificateResponseDTO;
import information.security.informationsecurity.service.admin.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@CrossOrigin
@PreAuthorize("hasAuthority('ADMIN')")
public class AdminController {

    private final AdminService adminService;

    /**
     * Get all CA users for certificate issuance
     */
    @GetMapping("/ca-users")
    public ResponseEntity<List<CAUserResponseDTO>> getAllCAUsers() {
        List<CAUserResponseDTO> caUsers = adminService.getAllCAUsers();
        return ResponseEntity.ok(caUsers);
    }

    /**
     * Issue CA certificate for a specific CA user
     */
    @PostMapping("/issue-ca-certificate")
    public ResponseEntity<CertificateResponseDTO> issueCACertificate(
            @RequestBody AdminCertificateRequestDTO request,
            Authentication authentication) {

        try {
            CertificateResponseDTO response = adminService.issueCACertificateForUser(
                    request, authentication.getName());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new CertificateResponseDTO(null, null, null, null, null, null, null, false, null, null, e.getMessage(), false));
        }
    }

    /**
     * Create new CA user
     */
    @PostMapping("/ca-users")
    public ResponseEntity<CAUserResponseDTO> createCAUser(
            @RequestBody CreateCAUserRequestDTO request,
            Authentication authentication) {

        try {
            CAUserResponseDTO response = adminService.createCAUser(request, authentication.getName());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Get CA user details
     */
    @GetMapping("/ca-users/{id}")
    public ResponseEntity<CAUserResponseDTO> getCAUser(@PathVariable Integer id) {
        try {
            CAUserResponseDTO caUser = adminService.getCAUser(id);
            return ResponseEntity.ok(caUser);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }
}