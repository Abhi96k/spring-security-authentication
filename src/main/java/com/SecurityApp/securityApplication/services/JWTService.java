package com.SecurityApp.securityApplication.services;

import com.SecurityApp.securityApplication.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JWTService {

    @Value("${jwt.secretKey}")
    private String jwtSecretKey;

    @Value("${jwt.expirationTime}")
    private long expirationTime;

    private SecretKey genSecretKey() {
        return Keys.hmacShaKeyFor(jwtSecretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(User user) {
        SecretKey key = genSecretKey();
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .subject(user.getUsername())
                .claim("userId", user.getId())
                .claim("email", user.getEmail())
                .claim("roles", user.getAuthorities())
                .issuedAt(new Date(now))
                .expiration(new Date(now + expirationTime))
                .signWith(key)
                .compact();
    }

    public String generateRefreshToken(User user) {
        SecretKey key = genSecretKey();
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .subject(user.getUsername())
                .claim("userId", user.getId())
                .claim("email", user.getEmail())
                .claim("roles", user.getAuthorities())
                .issuedAt(new Date(now))
                .expiration(new Date(now + expirationTime * 2)) // Refresh token valid for twice the access token duration
                .signWith(key)
                .compact();
    }
    // Retrieve all claims from a signed token.
    private Claims getAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(genSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // Retrieve user id from token.
    public Long getUserIdFromToken(String token) {
        return getAllClaims(token).get("userId", Long.class);
    }

    // Retrieve user email from token.
    public String getUserEmailFromToken(String token) {
        return getAllClaims(token).get("email", String.class);
    }

}
