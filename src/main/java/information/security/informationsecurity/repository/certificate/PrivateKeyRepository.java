package information.security.informationsecurity.repository.certificate;

import information.security.informationsecurity.model.certificate.PrivateKey;
import information.security.informationsecurity.model.certificate.Certificate;
import information.security.informationsecurity.model.auth.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PrivateKeyRepository extends JpaRepository<PrivateKey, Long> {

    // Find private key by certificate
    Optional<PrivateKey> findByCertificate(Certificate certificate);

    // Find private key by certificate ID
    Optional<PrivateKey> findByCertificateId(Long certificateId);

    // Check if private key exists for certificate
    boolean existsByCertificate(Certificate certificate);

    // Find private keys by owner
    List<PrivateKey> findByOwner(User owner);

    // Delete private key by certificate
    void deleteByCertificate(Certificate certificate);
}