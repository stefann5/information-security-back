package information.security.informationsecurity.repository.auth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<information.security.informationsecurity.model.auth.Token, Integer> {


    @Query("""
select t from Token t inner join User u on t.user.id = u.id
where t.user.id = :userId and t.loggedOut = false
""")
    List<information.security.informationsecurity.model.auth.Token> findAllAccessTokensByUser(Integer userId);

    Optional<information.security.informationsecurity.model.auth.Token> findByAccessToken(String token);

    Optional<information.security.informationsecurity.model.auth.Token > findByRefreshToken(String token);
}

