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

    // EXTRAE EL NOMBRE DEL TOKEN
    public String extractUsername(final String token) {
        final Claims jwtToken = Jwts.parser().verifyWith(getSignInKey()).build().parseSignedClaims(token).getPayload();
        return jwtToken.getSubject();
    }

    // GENERA EL TOKEN DE ACCESO
    public String generateToken(final User user) {
        return buildToken(user, jwtExpiration);
    }

    // GENERA EL TOKEN DE REFRESCO
    public String generateRefreshToken(final User user) {
        return buildToken(user, refreshExpiration);
    }

    // CONSTRUYE EL TOKEN (ACCESO Y REFRESCO)
    private String buildToken(final User user, final long expiration) {
        return Jwts.builder()
                .id(user.getId().toString())
                .claims(Map.of("username", user.getUsername()))
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis() + expiration))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey())
                .compact();
    }

    // COMPRUEBA QUE EL TOKEN ES VALIDO ASEGURANDOSE
    // QUE COINCIDE CON EL DEL USUARIO Y NO ESTA EXPIRADO
    public boolean isTokenValid(final String token, final User user) {
        final String username = extractUsername(token);
        return (username.equals(user.getUsername())) && !isTokenExpired(token);
    }

    // COMPRUEBA LA FECHA DE EXPIRACION DEL TOKEN
    private boolean isTokenExpired(final String token) {
        return extractExpiration(token).before(new Date());
    }

    // EXTRAE LA FECHA DE EXPIRACION DEL TOKEN
    private Date extractExpiration(final String token) {
        final Claims jwtToken = Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return jwtToken.getExpiration();
    }

    // GENERA UNA INSTANCIA DE secretKey PARA FIRMAR Y VALIDAR LOS TOKENS
    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
