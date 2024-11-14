package me.isra.users_auth.user;

import java.util.List;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import me.isra.users_auth.auth.repository.Token;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User {

    public record UserResponse(
            String username,
            String email

    ) {
    }

    @Id
    @GeneratedValue
    private Long id;

    @Column(unique = true)
    private String username;
    private String email;
    private String password;

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<Token> tokens;

}
