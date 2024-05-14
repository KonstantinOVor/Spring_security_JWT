package com.example.Spring_security_JWT.security.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.security.core.GrantedAuthority;
import java.security.Key;
import java.util.*;

@Component
@Slf4j
public class JwtUtil {
    @Value("${jwt.secret}")
    private String secretKey;
    @Value("${jwt.lifetime}")
    private long jwtLifetime;


    public String generateToken(UserDetails userDetails) {

        Map<String, Object> claims = createClaims(userDetails);
        Date issuedAt = new Date();
        Date expirationDate = generateExpirationDate();
        Key key = Keys.hmacShaKeyFor(secretKey.getBytes());
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(issuedAt)
                .setExpiration(expirationDate)
                .signWith(key)
                .compact();
    }

    private Date generateExpirationDate() {
        long milliseconds = jwtLifetime * 1000L;
        return new Date(System.currentTimeMillis() + milliseconds);
    }

    private Map<String, Object> createClaims(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        List <String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        claims.put("roles", roles);
        return claims;
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        if (validateTokenWithoutUserDetails(token)) {
            String username = getUsernameFromToken(token);
            return username != null && username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } else {
            return false;
        }
    }

    private boolean validateTokenWithoutUserDetails(String token) {
        try {
            Key key = Keys.hmacShaKeyFor(secretKey.getBytes());
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.error("Токен недействителен", e);
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        return parseToken(token).getSubject();
    }

    private boolean isTokenExpired(String token) {
        Date expiration = parseToken(token).getExpiration();
        return expiration.before(new Date());
    }

    public List<String> getRolesFromToken(String token) {
        Claims claims = parseToken(token);
        if (claims == null || !claims.containsKey("roles")) {
            return Collections.emptyList();
        }
        return claims.get("roles", List.class);
    }

    private Claims parseToken(String token) {

        Key key = Keys.hmacShaKeyFor(secretKey.getBytes());
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
