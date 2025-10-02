package information.security.informationsecurity.service.certificate;

import information.security.informationsecurity.dto.certificate.CertificateRequestDTO;
import information.security.informationsecurity.model.certificate.Certificate;
import information.security.informationsecurity.model.certificate.PrivateKey;
import information.security.informationsecurity.model.auth.User;
import information.security.informationsecurity.repository.certificate.PrivateKeyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

@Service
@RequiredArgsConstructor
public class CryptographyService {

    private final PrivateKeyRepository privateKeyRepository;

    @Value("${application.security.master-key:defaultMasterKey123}")
    private String masterKey;

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * Generate RSA or EC key pair
     */
    public KeyPair generateKeyPair(String algorithm, Integer keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen;

        if ("EC".equalsIgnoreCase(algorithm)) {
            keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(keySize != null ? keySize : 256);
        } else {
            keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySize != null ? keySize : 2048);
        }

        return keyGen.generateKeyPair();
    }

    /**
     * Create X.509 certificate
     */
    public X509Certificate createX509Certificate(CertificateRequestDTO request, KeyPair keyPair,
                                                 Certificate issuerCert, java.security.PrivateKey signingKey)
            throws Exception {

        // Build subject name
        X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        subjectBuilder.addRDN(BCStyle.CN, request.getCommonName());
        if (request.getOrganizationName() != null) {
            subjectBuilder.addRDN(BCStyle.O, request.getOrganizationName());
        }
        if (request.getOrganizationalUnit() != null) {
            subjectBuilder.addRDN(BCStyle.OU, request.getOrganizationalUnit());
        }
        if (request.getCountryCode() != null) {
            subjectBuilder.addRDN(BCStyle.C, request.getCountryCode());
        }
        if (request.getEmailAddress() != null) {
            subjectBuilder.addRDN(BCStyle.E, request.getEmailAddress());
        }
        if(request.getLocality() != null) {
            subjectBuilder.addRDN(BCStyle.L, request.getLocality());
        }
        if(request.getState() != null) {
            subjectBuilder.addRDN(BCStyle.ST, request.getState());
        }

        X500Name subject = subjectBuilder.build();

        // Issuer name
        X500Name issuer;
        if (issuerCert != null) {
            issuer = new X500Name(issuerCert.getSubjectDN());
        } else {
            issuer = subject; // Self-signed
        }

        // Serial number
        BigInteger serial = new BigInteger(64, new SecureRandom());

        // Validity dates
        Date notBefore = Date.from(request.getValidFrom().atZone(ZoneId.systemDefault()).toInstant());
        Date notAfter = Date.from(request.getValidTo().atZone(ZoneId.systemDefault()).toInstant());

        // Create certificate builder
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, keyPair.getPublic());

        // Add extensions
        addExtensions(certBuilder, request, keyPair.getPublic(), issuerCert);

        // Sign certificate
        java.security.PrivateKey privateKeyToUse = signingKey != null ? signingKey : keyPair.getPrivate();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(privateKeyToUse);

        X509CertificateHolder certHolder = certBuilder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);
    }

    /**
     * Parse Certificate Signing Request
     */
    public PKCS10CertificationRequest parseCSR(String csrPem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
            Object obj = parser.readObject();
            if (obj instanceof PKCS10CertificationRequest) {
                return (PKCS10CertificationRequest) obj;
            } else {
                throw new IllegalArgumentException("Invalid CSR format");
            }
        }
    }

    /**
     * Create certificate from CSR
     */
    public X509Certificate createCertificateFromCSR(PKCS10CertificationRequest csr,
                                                    Certificate issuerCert,
                                                    java.security.PrivateKey signingKey,
                                                    Integer validityDays) throws Exception {

        X500Name issuer = new X500Name(issuerCert.getSubjectDN());
        X500Name subject = csr.getSubject();

        BigInteger serial = new BigInteger(64, new SecureRandom());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + (validityDays * 24L * 60 * 60 * 1000));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, csr.getSubjectPublicKeyInfo());

        // Add basic extensions for CSR-based certificates
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(signingKey);

        X509CertificateHolder certHolder = certBuilder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);
    }

    /**
     * Convert certificate to PEM format
     */
    public String certificateToPEM(X509Certificate certificate) throws Exception {
        java.io.StringWriter writer = new java.io.StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(certificate);
        }
        return writer.toString();
    }

    /**
     * Save encrypted private key
     */
    public void saveEncryptedPrivateKey(Certificate certificate, java.security.PrivateKey privateKey, User owner)
            throws Exception {

        // Generate organization-specific encryption key
        SecretKey orgKey = generateOrganizationKey(owner.getOrganization());

        // Encrypt private key
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, orgKey);
        byte[] encryptedBytes = cipher.doFinal(privateKey.getEncoded());
        String encryptedPrivateKey = Base64.getEncoder().encodeToString(encryptedBytes);

        // Save to database
        PrivateKey privateKeyEntity = new PrivateKey();
        privateKeyEntity.setCertificate(certificate);
        privateKeyEntity.setEncryptedPrivateKey(encryptedPrivateKey);
        privateKeyEntity.setEncryptionAlgorithm("AES");
        privateKeyEntity.setKeySize(getKeySize(privateKey));
        privateKeyEntity.setOwner(owner);

        privateKeyRepository.save(privateKeyEntity);
    }

    /**
     * Get decrypted private key for certificate
     */
    public java.security.PrivateKey getDecryptedPrivateKey(Certificate certificate) throws Exception {
        PrivateKey privateKeyEntity = privateKeyRepository.findByCertificate(certificate)
                .orElseThrow(() -> new RuntimeException("Private key not found"));

        User user = certificate.getOwner();
        // Generate organization-specific decryption key
        SecretKey orgKey = generateOrganizationKey(user.getOrganization());

        // Decrypt private key
        byte[] encryptedBytes = Base64.getDecoder().decode(privateKeyEntity.getEncryptedPrivateKey());
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, orgKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Reconstruct private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decryptedBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Assume RSA for now

        return keyFactory.generatePrivate(keySpec);
    }

    // Private helper methods

    private void addExtensions(X509v3CertificateBuilder certBuilder, CertificateRequestDTO request,
                               PublicKey publicKey, Certificate issuerCert) throws Exception {

        // Subject Key Identifier
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(publicKey.getEncoded()));

        // Authority Key Identifier (for non-root certificates)
        if (!"ROOT_CA".equals(request.getCertificateType()) && issuerCert != null) {
            // This would need the issuer's public key - simplified for now
            certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(publicKey.getEncoded()));
        }

        //CRL Distribution Points (Where to check if certificate is withdrawn)
        if (!"ROOT_CA".equals(request.getCertificateType()) && issuerCert != null) {
            String crlURL = "http://localhost:8443/api/v1/pki/crl/" + issuerCert.getId();

            DistributionPointName distributionPointName = new DistributionPointName(
                    new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlURL)));
            DistributionPoint distributionPoint = new DistributionPoint(distributionPointName, null, null);
            CRLDistPoint crlDistPoint = new CRLDistPoint(new DistributionPoint[]{distributionPoint});

            certBuilder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);
        }

        //Authority Information Access (OCSP URL for realtime check)
        if (!"ROOT_CA".equals(request.getCertificateType()) && issuerCert != null) {
            String ocspURL = "http://localhost:8443/api/v1/pki/ocsp";

            AccessDescription ocspAccessDescription = new AccessDescription(
                    AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, ocspURL));
            AuthorityInformationAccess aia = new AuthorityInformationAccess(ocspAccessDescription);

            certBuilder.addExtension(Extension.authorityInfoAccess, false, aia);
        }

        // Key Usage
        int keyUsage = 0;
        if (request.getKeyUsage() != null) {
            for (String usage : request.getKeyUsage()) {
                keyUsage |= getKeyUsageValue(usage);
            }
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        }

        // Basic Constraints
        if (("ROOT_CA".equals(request.getCertificateType()) || "INTERMEDIATE_CA".equals(request.getCertificateType()))&&request.getPathLenConstraint() != null) {
            BasicConstraints basicConstraints = new BasicConstraints(request.getPathLenConstraint());
            certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
        }

        // Subject Alternative Names
        if (request.getSubjectAlternativeNames() != null && !request.getSubjectAlternativeNames().isEmpty()) {
            GeneralName[] altNames = request.getSubjectAlternativeNames().stream()
                    .map(san -> new GeneralName(GeneralName.dNSName, san))
                    .toArray(GeneralName[]::new);

            certBuilder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(altNames));
        }
    }

    private int getKeyUsageValue(String usage) {
        switch (usage.toUpperCase()) {
            case "DIGITAL_SIGNATURE": return KeyUsage.digitalSignature;
            case "KEY_ENCIPHERMENT": return KeyUsage.keyEncipherment;
            case "KEY_CERT_SIGN": return KeyUsage.keyCertSign;
            case "CRL_SIGN": return KeyUsage.cRLSign;
            case "NON_REPUDIATION": return KeyUsage.nonRepudiation;
            case "DATA_ENCIPHERMENT": return KeyUsage.dataEncipherment;
            case "KEY_AGREEMENT": return KeyUsage.keyAgreement;
            case "ENCIPHER_ONLY": return KeyUsage.encipherOnly;
            case "DECIPHER_ONLY": return KeyUsage.decipherOnly;
            default: return 0;
        }
    }

    private SecretKey generateOrganizationKey(String organization) throws Exception {
        // Create organization-specific key using master key and organization name
        String keyMaterial = masterKey + ":" + organization;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(keyMaterial.getBytes());

        // Use first 16 bytes for AES-128
        byte[] keyBytes = new byte[16];
        System.arraycopy(hash, 0, keyBytes, 0, 16);

        return new SecretKeySpec(keyBytes, "AES");
    }

    private Integer getKeySize(java.security.PrivateKey privateKey) {
        if (privateKey instanceof java.security.interfaces.RSAPrivateKey) {
            return ((java.security.interfaces.RSAPrivateKey) privateKey).getModulus().bitLength();
        }
        return null;
    }

    /**
     * Create keystore containing certificate and private key (for autogenerate flow)
     */
    public byte[] createKeystoreWithPrivateKey(
            X509Certificate certificate,
            java.security.PrivateKey privateKey,
            information.security.informationsecurity.model.certificate.Certificate issuerCert,
            String password,
            String keystoreType,
            String alias) throws Exception {

        // Create keystore
        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        keyStore.load(null, null);

        // Build certificate chain
        java.security.cert.Certificate[] certChain;

        if (issuerCert != null) {
            // Load issuer certificate from PEM
            X509Certificate issuerX509 = loadX509CertificateFromPEM(issuerCert.getCertificateData());

            // Build chain: [end-entity cert, issuer cert]
            // X509Certificate extends java.security.cert.Certificate, tako da je cast implicitni
            certChain = new java.security.cert.Certificate[] { (java.security.cert.Certificate) certificate,  (java.security.cert.Certificate) issuerX509 };
        } else {
            // Self-signed certificate
            certChain = new java.security.cert.Certificate[] { (java.security.cert.Certificate) certificate };
        }

        // Store private key with certificate chain
        // Sad je tip ispravan: java.security.cert.Certificate[]
        keyStore.setKeyEntry(
                alias,
                privateKey,
                password.toCharArray(),
                certChain
        );

        // Convert keystore to byte array
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        keyStore.store(outputStream, password.toCharArray());

        return outputStream.toByteArray();
    }

    /**
     * Helper method to load X.509 certificate from PEM string
     */
    private X509Certificate loadX509CertificateFromPEM(String pemData) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pemData))) {
            Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder) {
                return new JcaX509CertificateConverter()
                        .setProvider("BC")
                        .getCertificate((X509CertificateHolder) obj);
            } else if (obj instanceof X509Certificate) {
                return (X509Certificate) obj;
            } else {
                throw new IllegalArgumentException("Invalid certificate format");
            }
        }
    }
}