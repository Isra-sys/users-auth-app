package me.isra.users_auth.user;

import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.AllArgsConstructor;
import me.isra.users_auth.auth.repository.Token;
import me.isra.users_auth.auth.repository.TokenRepository;
import me.isra.users_auth.user.User.UserResponse;

@RestController
@RequestMapping
@AllArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;

    @GetMapping("/users")
    public List<UserResponse> getUsers() {
        final var users = userRepository.findAll();
        return users.stream()
                .map(user -> new UserResponse(user.getUsername(), user.getEmail()))
                .toList();
    }

    @PostMapping("/profile")
    public UserResponse getUserFromToken(@RequestHeader(HttpHeaders.AUTHORIZATION) final String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Token no válido");
        }

        String token = authHeader.substring(7);

        Optional<Token> foundToken = tokenRepository.findByToken(token);

        if (foundToken.isEmpty() || foundToken.get().getUser() == null) {
            throw new IllegalArgumentException("Token no válido o no asociado a ningún usuario");
        }

        User user = foundToken.get().getUser();

        return new UserResponse(user.getUsername(), user.getEmail());
    }

}
