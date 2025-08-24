package information.security.informationsecurity.repository.user;

import information.security.informationsecurity.model.auth.CAUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CARepository extends JpaRepository<CAUser, Integer> {
    Optional<CAUser> findByUsername(String username);
}
