package me.isra.users_auth.user;

import java.util.List;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import me.isra.users_auth.auth.repository.Token;
import me.isra.users_auth.auth.repository.TokenRepository;
import me.isra.users_auth.user.User.UserResponse;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;

    public List<UserResponse> getAllUsers() {
        final var users = userRepository.findAll();
        return users.stream()
                .map(user -> new UserResponse(user.getUsername(), user.getEmail()))
                .toList();
    }

    public UserResponse getUserFromToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Token no válido");
        }

        String token = authHeader.substring(7);
        Token foundToken = tokenRepository.findByToken(token).orElseThrow();
        User user = foundToken.getUser();

        if (user == null) {
            throw new IllegalArgumentException("Token no válido o no asociado a ningún usuario");
        }

        return new UserResponse(user.getUsername(), user.getEmail());
    }
}
