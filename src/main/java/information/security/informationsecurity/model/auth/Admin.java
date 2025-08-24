package information.security.informationsecurity.model.auth;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.persistence.*;

import java.util.List;

@Entity
@Data
@AllArgsConstructor
@DiscriminatorValue("Admin")
public class Admin extends User {

}