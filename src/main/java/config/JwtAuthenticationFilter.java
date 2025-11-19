package config; // O donde pongas tus clases de configuración

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils; 
import org.springframework.web.filter.OncePerRequestFilter;
import servicios.UsuariosServicio; 

import java.io.IOException;

@Component 
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider tokenProvider; // Asumo que se llama así

    @Autowired
    private UsuariosServicio usuariosServicio; 

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                        HttpServletResponse response, 
                                        FilterChain filterChain) throws ServletException, IOException {
        
        // --- ¡CORRECCIÓN APLICADA AQUÍ! ---
        // Comprobamos la ruta que ve Spring (sin el context-path)
        if (request.getServletPath().contains("/auth")) {
            filterChain.doFilter(request, response);
            return; // Salimos del filtro inmediatamente.
        }
        // --- FIN DE LA CORRECCIÓN ---

        try {
            // 1. Obtener el token del header "Authorization"
            String jwt = getJwtFromRequest(request);

            // 2. Validar el token
            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                
                // 3. Obtener el email (username) del token
                String email = tokenProvider.getUsernameFromJWT(jwt); 
                
                // 4. Cargar el usuario (UserDetails) desde la BBDD
                UserDetails userDetails = usuariosServicio.loadUserByUsername(email);
                
                // 5. Crear el objeto de autenticación
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 6. Establecer al usuario como "autenticado" en el contexto
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            
            logger.error("No se pudo establecer la autenticación del usuario", ex);
        }

        filterChain.doFilter(request, response); // Continuar con el resto de filtros
    }

    /**
     * Método auxiliar para extraer el "Bearer <token>" del header
     */
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }
}