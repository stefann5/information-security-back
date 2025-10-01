package information.security.informationsecurity.controller.certificate;

import information.security.informationsecurity.service.certificate.OCSPService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/pki/ocsp")
@RequiredArgsConstructor
@CrossOrigin
public class OCSPController {
    private final OCSPService service;

    /**
     * OCSP Request via POST (binary)
     */
    @PostMapping(consumes = "application/ocsp-request", produces = "application/ocsp-response")
    public ResponseEntity<byte[]> handleOCSPRequest(@RequestBody byte[] ocspRequest) {
        try {
            byte[] ocspResponse = service.processOCSPRequest(ocspRequest);
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/ocsp-response"))
                    .body(ocspResponse);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * OCSP Request via GET (Base64 encoded)
     */
    @GetMapping("/{encodedRequest}")
    public ResponseEntity<byte[]> handleOCSPRequest(@PathVariable String encodedRequest) {
        try {
            byte[] ocspResponse = service.processOCSPRequestFromBase64(encodedRequest);
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/ocsp-response"))
                    .body(ocspResponse);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Check certificate status via simple GET
     */
    @GetMapping("/status/{serialNumber}")
    public ResponseEntity<String> getCertificateStatus(@PathVariable String serialNumber) {
        try {
            boolean revoked = service.isCertificateRevoked(serialNumber);
            return ResponseEntity.ok(revoked ? "REVOKED" : "GOOD");
        } catch (Exception e) {
            return ResponseEntity.ok("UNKNOWN");
        }
    }
}
