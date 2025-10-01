package information.security.informationsecurity.service.certificate;

import information.security.informationsecurity.model.certificate.Certificate;
import information.security.informationsecurity.repository.certificate.CertificateRepository;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class OCSPService {

    private final CertificateRepository certificateRepository;
    private final CryptographyService cryptographyService;

    /**
     * Obrađuje OCSP zahtev i generiše odgovor
     * OCSP zahtev = "Da li je sertifikat sa serial brojem X valjan?"
     * OCSP odgovor = "GOOD" ili "REVOKED" sa razlogom
     */
    public byte[] processOCSPRequest(byte[] ocspRequestBytes) throws Exception {
        // Korak 1: Parsiramo OCSP zahtev
        OCSPReq ocspRequest = new OCSPReq(ocspRequestBytes);
        Req[] requests = ocspRequest.getRequestList();

        // Korak 2: Pravimo OCSP odgovor builder
        OCSPRespBuilder responseBuilder = new OCSPRespBuilder();

        // Korak 3: Proveravamo da li ima zahteva
        if (requests.length == 0) {
            return responseBuilder.build(OCSPRespBuilder.MALFORMED_REQUEST, null).getEncoded();
        }

        // Korak 4: Obrađujemo prvi zahtev (pojednostavljeno - obično bi bilo više)
        Req req = requests[0];
        CertificateID certID = req.getCertID();

        // Korak 5: Tražimo sertifikat po serial broju
        // Izvlačimo serial number iz CertificateID objekta
        BigInteger serialNumber = certID.getSerialNumber();
        Certificate certificate = certificateRepository.findBySerialNumber(serialNumber.toString())
                .orElse(null);

        if (certificate == null) {
            // Sertifikat ne postoji u našoj bazi
            return responseBuilder.build(OCSPRespBuilder.UNAUTHORIZED, null).getEncoded();
        }

        // Korak 6: Tražimo issuer sertifikat (ko je izdao ovaj sertifikat)
        Certificate issuerCert = certificate.getIssuerCertificate();
        if (issuerCert == null) {
            return responseBuilder.build(OCSPRespBuilder.UNAUTHORIZED, null).getEncoded();
        }

        // Korak 7: Pravimo basic OCSP odgovor
        X509Certificate issuerX509 = parseX509Certificate(issuerCert.getCertificateData());
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
                issuerX509.getPublicKey().getEncoded()
        );
        BasicOCSPRespBuilder basicResponseBuilder = new BasicOCSPRespBuilder(
                new RespID(ResponderID.getInstance(subjectPublicKeyInfo))
        );

        // Korak 8: Proveravamo status sertifikata
        CertificateStatus certStatus;
        if (certificate.isRevoked()) {
            // Sertifikat je povučen - vraćamo REVOKED sa datumom i razlogom
            Date revocationDate = Date.from(certificate.getRevocationDate()
                    .atZone(ZoneId.systemDefault()).toInstant());
            int reason = mapRevocationReasonToOCSP(certificate.getRevocationReason());
            certStatus = new RevokedStatus(revocationDate, reason);
        } else {
            // Sertifikat je valjan - vraćamo GOOD
            certStatus = CertificateStatus.GOOD;
        }

        // Korak 9: Dodajemo response sa statusom
        Date thisUpdate = new Date(); // Kada je odgovor napravljen
        Date nextUpdate = new Date(System.currentTimeMillis() + (24 * 60 * 60 * 1000)); // Sledeće ažuriranje za 24h

        basicResponseBuilder.addResponse(certID, certStatus, thisUpdate, nextUpdate, null);

        // Korak 10: Dodajemo nonce (broj koji se koristi samo jednom) ako postoji u zahtevu
        Extension nonceExtension = ocspRequest.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (nonceExtension != null) {
            basicResponseBuilder.setResponseExtensions(
                    new Extensions(nonceExtension)
            );
        }

        // Korak 11: Potpisujemo odgovor privatnim ključem CA-a
        java.security.PrivateKey signingKey = cryptographyService.getDecryptedPrivateKey(issuerCert);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(signingKey);

        // Konvertujemo X509Certificate u X509CertificateHolder
        X509CertificateHolder[] chain = new X509CertificateHolder[] {
                new JcaX509CertificateHolder(issuerX509)
        };

        BasicOCSPResp basicResponse = basicResponseBuilder.build(
                signer,
                chain,
                new Date()
        );

        // Korak 12: Vraćamo finalni OCSP odgovor
        return responseBuilder.build(OCSPRespBuilder.SUCCESSFUL, basicResponse).getEncoded();
    }

    /**
     * Obrađuje OCSP zahtev iz Base64 stringa (GET zahtev)
     */
    public byte[] processOCSPRequestFromBase64(String encodedRequest) throws Exception {
        byte[] requestBytes = Base64.getDecoder().decode(encodedRequest);
        return processOCSPRequest(requestBytes);
    }

    /**
     * Jednostavna provera da li je sertifikat povučen
     */
    public boolean isCertificateRevoked(String serialNumber) {
        return certificateRepository.findBySerialNumber(serialNumber)
                .map(Certificate::isRevoked) // Vraća true/false
                .orElse(false); // Ako sertifikat ne postoji, nije povučen
    }

    /**
     * Parsira PEM sertifikat u X509Certificate objekat
     */
    private X509Certificate parseX509Certificate(String pemData) throws Exception {
        // Uklanjamo PEM header/footer ako postoje
        String certificateData = pemData
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

        byte[] decodedCert = Base64.getDecoder().decode(certificateData);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream inputStream = new ByteArrayInputStream(decodedCert);
        return (X509Certificate) factory.generateCertificate(inputStream);
    }

    /**
     * Mapira naš enum razlog povlačenja u OCSP standard razlog
     */
    private int mapRevocationReasonToOCSP(
            information.security.informationsecurity.model.certificate.RevocationReason reason) {
        if (reason == null) {
            return org.bouncycastle.asn1.x509.CRLReason.unspecified;
        }

        switch (reason) {
            case KEY_COMPROMISE:
                return org.bouncycastle.asn1.x509.CRLReason.keyCompromise;
            case CA_COMPROMISE:
                return org.bouncycastle.asn1.x509.CRLReason.cACompromise;
            case AFFILIATION_CHANGED:
                return org.bouncycastle.asn1.x509.CRLReason.affiliationChanged;
            case SUPERSEDED:
                return org.bouncycastle.asn1.x509.CRLReason.superseded;
            case CESSATION_OF_OPERATION:
                return org.bouncycastle.asn1.x509.CRLReason.cessationOfOperation;
            case CERTIFICATE_HOLD:
                return org.bouncycastle.asn1.x509.CRLReason.certificateHold;
            default:
                return org.bouncycastle.asn1.x509.CRLReason.unspecified;
        }
    }
}