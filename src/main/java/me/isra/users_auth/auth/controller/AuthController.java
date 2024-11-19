package me.isra.users_auth.auth.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import lombok.RequiredArgsConstructor;
import me.isra.users_auth.auth.repository.Token.TokenResponse;
import me.isra.users_auth.auth.service.AuthService;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    public record LoginRequest(
            String username,
            String password) {
    }

    public record RegisterRequest(
            String username,
            String email,
            String password) {
    }

    private final AuthService service;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody final RegisterRequest request) {
        final String response = service.register(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> authenticate(@RequestBody final LoginRequest request) {
        final TokenResponse token = service.login(request);
        return ResponseEntity.ok(token);
    }

    @PostMapping("/refresh")
    public TokenResponse refreshToken(@RequestHeader(HttpHeaders.AUTHORIZATION) final String authHeader) {
        return service.refreshToken(authHeader);
    }
}
