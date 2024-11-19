package me.isra.users_auth.auth.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenRepository extends JpaRepository<Token, Long> {
    List<Token> findAllValidTokensByUserId(Long id);

    Optional<Token> findByToken(String jwtToken);
}
