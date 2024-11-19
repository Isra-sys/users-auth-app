package me.isra.users_auth.user;

import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import me.isra.users_auth.user.User.UserResponse;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService service;

    @GetMapping("/all")
    public ResponseEntity<List<UserResponse>> getUsers() {
        List<UserResponse> response = service.getAllUsers();
        return ResponseEntity.ok(response);
    }

    @PostMapping("/profile")
    public ResponseEntity<UserResponse> getUserFromToken(
            @RequestHeader(HttpHeaders.AUTHORIZATION) final String authHeader) {
        UserResponse response = service.getUserFromToken(authHeader);
        return ResponseEntity.ok(response);
    }
}
