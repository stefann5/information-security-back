package information.security.informationsecurity.service.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImp implements UserDetailsService {

    private final information.security.informationsecurity.repository.user.UserRepository repository;

    public UserDetailsServiceImp(information.security.informationsecurity.repository.user.UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return information.security.informationsecurity.config.UserFactory.create(repository.findByUsername(username)
                .orElseThrow(()-> new UsernameNotFoundException("User not found")));
    }
}
