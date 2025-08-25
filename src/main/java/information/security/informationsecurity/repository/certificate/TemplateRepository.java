package information.security.informationsecurity.repository.certificate;

import information.security.informationsecurity.model.certificate.Template;
import information.security.informationsecurity.model.certificate.Certificate;
import information.security.informationsecurity.model.auth.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TemplateRepository extends JpaRepository<Template, Long> {

    // Find templates by creator
    List<Template> findByCreatedBy(User createdBy);

    // Find templates by CA issuer
    List<Template> findByCaIssuer(Certificate caIssuer);

    // Find template by name
    Optional<Template> findByTemplateName(String templateName);

    // Find templates that can be used by a specific CA user
    @Query("SELECT t FROM Template t WHERE t.caIssuer.owner = :caUser OR t.createdBy = :caUser")
    List<Template> findAvailableTemplatesForUser(@Param("caUser") User caUser);

    // Check if template name exists
    boolean existsByTemplateName(String templateName);
}