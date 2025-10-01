package information.security.informationsecurity.controller.certificate;

import information.security.informationsecurity.service.certificate.CRLService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/pki/crl")
@RequiredArgsConstructor
@CrossOrigin
public class CRLController {
    private final CRLService service;

    /**
     * Get CRL for specific CA certificate
     * */
    @GetMapping(value = "/{caId}", produces = "application/pkcs7-crl")
    public ResponseEntity<byte[]> getCRL(@PathVariable Long caId) {
        try {
            byte[] crlBytes = service.generateCRL(caId);
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/pkcs7-crl"))
                    .header("Content-Disposition", "attachment; filename=ca-" + caId + ".crl")
                    .body(crlBytes);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Get CRL in PEM format
     * */
    @GetMapping(value = "/{caId}/pem", produces = "application/x-pem-file")
    public ResponseEntity<String> getCRLPEM(@PathVariable Long caId) {
        try {
            String crlPem = service.generateCRLPEM(caId);
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/x-pem-file"))
                    .body(crlPem);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }
}
