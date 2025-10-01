package information.security.informationsecurity.service.certificate;

import information.security.informationsecurity.model.certificate.Certificate;
import information.security.informationsecurity.repository.certificate.CertificateRepository;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.StringWriter;
import java.math.BigInteger;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
public class CRLService {
    private final CertificateRepository certificateRepository;
    private final CryptographyService cryptographyService;

    public byte[] generateCRL(long caId) throws Exception {
        Certificate caCertificate = certificateRepository.findById(caId)
                .orElseThrow(() -> new RuntimeException("CA certificate not found"));

        // Get all revoked certificates issued by this CA
        List<Certificate> revokedCertificates = certificateRepository
                .findByIssuerCertificateAndRevokedTrue(caCertificate);

        // Build CRL
        X500Name issuerName = new X500Name(caCertificate.getSubjectDN());
        Date thisUpdate = new Date();
        Date nextUpdate = new Date(System.currentTimeMillis() + (24 * 60 * 60 * 1000)); // 24 hours

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerName, thisUpdate);
        crlBuilder.setNextUpdate(nextUpdate);

        // Add revoked certificates
        for (Certificate revokedCert : revokedCertificates) {
            BigInteger serialNumber = new BigInteger(revokedCert.getSerialNumber());
            Date revocationDate = Date.from(revokedCert.getRevocationDate()
                    .atZone(ZoneId.systemDefault()).toInstant());

            int reasonCode = mapRevocationReasonToCRLReason(revokedCert.getRevocationReason());
            crlBuilder.addCRLEntry(serialNumber, revocationDate, reasonCode);
        }

        // Add CRL Number extension
        long crlNumber = System.currentTimeMillis() / 1000; // Simple CRL numbering
        crlBuilder.addExtension(Extension.cRLNumber, false,
                new org.bouncycastle.asn1.ASN1Integer(crlNumber));

        // Sign CRL
        java.security.PrivateKey signingKey = cryptographyService.getDecryptedPrivateKey(caCertificate);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(signingKey);

        X509CRLHolder crlHolder = crlBuilder.build(signer);
        return crlHolder.getEncoded();
    }

    public String generateCRLPEM(Long caId) throws Exception {
        byte[] crlBytes = generateCRL(caId);
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509", "BC");
        java.security.cert.X509CRL x509CRL = (java.security.cert.X509CRL) cf.generateCRL(new java.io.ByteArrayInputStream(crlBytes));

        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(x509CRL);
        }
        return stringWriter.toString();
    }

    private int mapRevocationReasonToCRLReason(
            information.security.informationsecurity.model.certificate.RevocationReason reason) {
        if (reason == null) {
            return CRLReason.unspecified;
        }

        return switch (reason) {
            case KEY_COMPROMISE -> CRLReason.keyCompromise;
            case CA_COMPROMISE -> CRLReason.cACompromise;
            case AFFILIATION_CHANGED -> CRLReason.affiliationChanged;
            case SUPERSEDED -> CRLReason.superseded;
            case CESSATION_OF_OPERATION -> CRLReason.cessationOfOperation;
            case CERTIFICATE_HOLD -> CRLReason.certificateHold;
            default -> CRLReason.unspecified;
        };
    }
}
