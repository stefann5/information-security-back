package information.security.informationsecurity.repository.user;

import information.security.informationsecurity.model.auth.Admin;
import information.security.informationsecurity.model.auth.CommonUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CommonUserRepository extends JpaRepository<CommonUser, Integer> {
    Optional<CommonUser> findByUsername(String username);
}