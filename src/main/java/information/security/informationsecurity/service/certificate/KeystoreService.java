package information.security.informationsecurity.service.certificate;

import information.security.informationsecurity.dto.certificate.KeystoreDownloadDTO;
import information.security.informationsecurity.model.certificate.Certificate;
import information.security.informationsecurity.model.auth.User;
import information.security.informationsecurity.repository.certificate.CertificateRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class KeystoreService {

    private final CertificateRepository certificateRepository;
    private final CryptographyService cryptographyService;
    private final ValidationService validationService;

    /**
     * Create and return keystore bytes containing certificate and private key
     */
    public byte[] createKeystore(KeystoreDownloadDTO request, User currentUser) throws Exception {
        // Get certificate
        Certificate certificate = certificateRepository.findById(request.getCertificateId())
                .orElseThrow(() -> new RuntimeException("Certificate not found"));

        // Validate access
        validationService.validateCertificateAccess(certificate, currentUser);

        // Create keystore
        KeyStore keystore = KeyStore.getInstance(request.getKeystoreType());
        keystore.load(null, request.getKeystorePassword().toCharArray());

        // Convert PEM certificate to X509Certificate
        X509Certificate x509Cert = convertPEMToX509(certificate.getCertificateData());

        // Get private key
        java.security.PrivateKey privateKey = cryptographyService.getDecryptedPrivateKey(certificate, currentUser);

        // Build certificate chain
        List<X509Certificate> certChain = buildCertificateChain(certificate);

        // Add certificate and private key to keystore
        keystore.setKeyEntry(
                request.getAlias() != null ? request.getAlias() : "certificate",
                privateKey,
                request.getKeystorePassword().toCharArray(),
                certChain.toArray(new X509Certificate[0])
        );

        // Convert keystore to bytes
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        keystore.store(outputStream, request.getKeystorePassword().toCharArray());

        return outputStream.toByteArray();
    }

    /**
     * Create keystore with only certificate (no private key) for distribution
     */
    public byte[] createCertificateOnlyKeystore(Long certificateId, String password,
                                                String keystoreType, String alias, User currentUser) throws Exception {

        Certificate certificate = certificateRepository.findById(certificateId)
                .orElseThrow(() -> new RuntimeException("Certificate not found"));

        validationService.validateCertificateAccess(certificate, currentUser);

        KeyStore keystore = KeyStore.getInstance(keystoreType);
        keystore.load(null, password.toCharArray());

        X509Certificate x509Cert = convertPEMToX509(certificate.getCertificateData());

        keystore.setCertificateEntry(
                alias != null ? alias : "certificate",
                x509Cert
        );

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        keystore.store(outputStream, password.toCharArray());

        return outputStream.toByteArray();
    }

    /**
     * Create truststore containing CA certificates
     */
    public byte[] createTruststore(List<Long> certificateIds, String password,
                                   String keystoreType, User currentUser) throws Exception {

        KeyStore truststore = KeyStore.getInstance(keystoreType);
        truststore.load(null, password.toCharArray());

        for (int i = 0; i < certificateIds.size(); i++) {
            int finalI = i;
            Certificate certificate = certificateRepository.findById(certificateIds.get(i))
                    .orElseThrow(() -> new RuntimeException("Certificate not found: " + certificateIds.get(finalI)));

            validationService.validateCertificateAccess(certificate, currentUser);

            X509Certificate x509Cert = convertPEMToX509(certificate.getCertificateData());

            truststore.setCertificateEntry("ca-" + i, x509Cert);
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        truststore.store(outputStream, password.toCharArray());

        return outputStream.toByteArray();
    }

    // Private helper methods

    private X509Certificate convertPEMToX509(String pemData) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream inputStream = new ByteArrayInputStream(pemData.getBytes());
        return (X509Certificate) factory.generateCertificate(inputStream);
    }

    private List<X509Certificate> buildCertificateChain(Certificate certificate) throws Exception {
        List<X509Certificate> chain = new ArrayList<>();

        // Add the certificate itself
        chain.add(convertPEMToX509(certificate.getCertificateData()));

        // Add parent certificates up to root
        Certificate parent = certificate.getIssuerCertificate();
        while (parent != null) {
            chain.add(convertPEMToX509(parent.getCertificateData()));
            parent = parent.getIssuerCertificate();
        }

        return chain;
    }
}