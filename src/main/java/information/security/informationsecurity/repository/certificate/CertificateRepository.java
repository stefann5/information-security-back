package information.security.informationsecurity.repository.certificate;

import information.security.informationsecurity.model.certificate.Certificate;
import information.security.informationsecurity.model.certificate.CertificateType;
import information.security.informationsecurity.model.auth.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    // Find by serial number
    Optional<Certificate> findBySerialNumber(String serialNumber);

    // Find certificates by owner
    List<Certificate> findByOwnerAndRevokedFalse(User owner);

    List<Certificate> findByOwner(User owner);

    List<Certificate> findByRevokedFalse();

    // Find certificates by type
    List<Certificate> findByCertificateTypeAndRevokedFalse(CertificateType certificateType);

    // Find CA certificates that can be used for signing
    @Query("SELECT c FROM Certificate c WHERE c.certificateType IN ('ROOT_CA', 'INTERMEDIATE_CA') " +
            "AND c.revoked = false AND c.validTo > :now")
    List<Certificate> findValidCACertificates(@Param("now") LocalDateTime now);

    // Find certificates issued by a specific CA
    List<Certificate> findByIssuerCertificateAndRevokedFalse(Certificate issuerCertificate);

    // Find certificates in a certificate chain
    @Query("SELECT c FROM Certificate c WHERE c.issuerCertificate = :issuer OR c.id = :issuerId")
    List<Certificate> findCertificateChain(@Param("issuer") Certificate issuer, @Param("issuerId") Long issuerId);

    // Find certificates by owner that are CA certificates
    @Query("SELECT c FROM Certificate c WHERE c.owner = :owner " +
            "AND c.certificateType IN ('ROOT_CA', 'INTERMEDIATE_CA') AND c.revoked = false")
    List<Certificate> findCACertificatesByOwner(@Param("owner") User owner);

    // Find expiring certificates
    @Query("SELECT c FROM Certificate c WHERE c.validTo BETWEEN :now AND :futureDate AND c.revoked = false")
    List<Certificate> findExpiringCertificates(@Param("now") LocalDateTime now,
                                               @Param("futureDate") LocalDateTime futureDate);

    // Find revoked certificates for CRL
    List<Certificate> findByRevokedTrueAndRevocationDateAfter(LocalDateTime since);

    // Check if certificate with subject DN already exists
    boolean existsBySubjectDNAndRevokedFalse(String subjectDN);

    // Find certificates by common name
    @Query("SELECT c FROM Certificate c WHERE c.subjectDN LIKE %:commonName% AND c.revoked = false")
    List<Certificate> findByCommonName(@Param("commonName") String commonName);


}