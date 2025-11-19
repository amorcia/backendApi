package config;

// --- IMPORTS AÑADIDOS ---
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException; // Importante
import org.slf4j.Logger; // Para logging de errores
import org.slf4j.LoggerFactory; // Para logging de errores
// --- FIN IMPORTS AÑADIDOS ---

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider {

    // --- Logger para registrar errores de validación ---
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    // 1. Clave secreta (existente)
    private final Key jwtSecretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    // 2. Tiempo de expiración (existente)
    private final long jwtExpirationInMs = 1000 * 60 * 60; // 1 hora

    /**
     * Genera un token JWT para un usuario que se ha logueado con éxito.
     * (Método existente - sin cambios)
     */
    public String generateToken(Authentication authentication) {
        
        String username = authentication.getName(); // El email del usuario
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(jwtSecretKey, SignatureAlgorithm.HS512)
                .compact();
    }

    // ---
    // --- MÉTODOS AÑADIDOS QUE FALTABAN ---
    // ---

    /**
     * Obtiene el email (username) del token JWT.
     * Este método es llamado por JwtAuthenticationFilter.
     */
    public String getUsernameFromJWT(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(jwtSecretKey) // Usa la misma clave para "abrir" el token
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject(); // Devuelve el email (el "subject")
    }

    /**
     * Valida si un token JWT es correcto y no ha expirado.
     * Este método es llamado por JwtAuthenticationFilter.
     */
    public boolean validateToken(String authToken) {
        try {
            // Intenta "abrir" el token con la clave secreta
            Jwts.parserBuilder()
                .setSigningKey(jwtSecretKey)
                .build()
                .parseClaimsJws(authToken);
            
            // Si no hay excepción, el token es válido
            return true;
        } catch (SignatureException ex) {
            logger.error("Firma JWT inválida: {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            logger.error("Token JWT malformado: {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            logger.error("Token JWT expirado: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            logger.error("Token JWT no soportado: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            logger.error("Argumento JWT ilegal: {}", ex.getMessage());
        }
        
        // Si hay cualquier excepción, el token es inválido
        return false;
    }
}