package com.universidad.seguridad.security;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

    // En un proyecto real, esta clave vive en application.properties o
    // en una variable de entorno, NUNCA hardcodeada en el código fuente
    // comprometido al repositorio (ver Decisión de diseño más abajo).
    private final SecretKey clave =
        Keys.hmacShaKeyFor("clave-secreta-minimo-32-caracteres-laboratorio".getBytes());

    private static final long EXPIRACION_MS = 3_600_000; // 1 hora

    public String generarToken(String email, String rol) {
        return Jwts.builder()
            .subject(email)
            .claim("rol", rol)
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + EXPIRACION_MS))
            .signWith(clave)
            .compact();
    }

    public String extraerEmail(String token) {
        return parsearClaims(token).getSubject();
    }

    public String extraerRol(String token) {
        return parsearClaims(token).get("rol", String.class);
    }

    public boolean esValido(String token) {
        try {
            parsearClaims(token); // lanza excepción si la firma o la
                                   // expiración no son válidas
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false; // firma inválida, token expirado o malformado
        }
    }

    private Claims parsearClaims(String token) {
        return Jwts.parser()
            .verifyWith(clave)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }
}