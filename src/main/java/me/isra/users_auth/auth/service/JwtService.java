package me.isra.users_auth.auth.service;

import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import me.isra.users_auth.user.User;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    public String extractUsername(final String token) {
        final Claims jwtToken = Jwts.parser().verifyWith(getSignInKey()).build().parseSignedClaims(token).getPayload();
        return jwtToken.getSubject();
    }

    public String generateToken(final User user) {
        return buildToken(user, jwtExpiration, "access");
    }

    public String generateRefreshToken(final User user) {
        return buildToken(user, refreshExpiration, "refresh");
    }

    private String buildToken(final User user, final long expiration, final String type) {
        return Jwts.builder()
                .id(user.getId().toString())
                .claims(Map.of("username", user.getUsername(), "type", type))
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis() + expiration))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey())
                .compact();
    }

    public boolean isTokenValid(final String token, final User user) {
        final String username = extractUsername(token);
        return (username.equals(user.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(final String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(final String token) {
        final Claims jwtToken = Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return jwtToken.getExpiration();
    }

    public boolean isAccessToken(final String token) {
        final Claims claims = extractAllClaims(token);
        return "access".equals(claims.get("type"));
    }
    
    public boolean isRefreshToken(final String token) {
        final Claims claims = extractAllClaims(token);
        return "refresh".equals(claims.get("type"));
    }
    
    private Claims extractAllClaims(final String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
