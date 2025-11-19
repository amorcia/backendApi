package config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod; 
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter; 
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import servicios.UsuariosServicio; 

import java.util.Arrays; 

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UsuariosServicio servicioUsuarios; 
    
    @Autowired
    private PasswordEncoder codificadorContrasena;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter; 

    @Bean
    public AuthenticationManager gestorAutenticacion(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(servicioUsuarios) 
                .passwordEncoder(codificadorContrasena)
                .and()
                .build();
    }

    @Bean
    public SecurityFilterChain cadenaFiltrosSeguridad(HttpSecurity http) throws Exception {
        
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                // --- ¡CORRECCIÓN APLICADA AQUÍ! ---
                // Spring Security no ve el "context-path" (/taskflow),
                // por lo que la regla debe ser sobre la ruta que queda: "/auth/**"
                .requestMatchers("/auth/**").permitAll() 
                
                // Protegemos "/usuarios" (Spring lo ve como /usuarios/**)
                .requestMatchers("/usuarios/**").authenticated() 
                
                // Cualquier otra petición requiere autenticación
                .anyRequest().authenticated() 
            )
            
            // Añadimos el filtro JWT en el lugar correcto
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Define las reglas de CORS (¡Correcto!)
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Acepta peticiones de CUALQUIER origen
        configuration.setAllowedOrigins(Arrays.asList("*")); 
        
        // Acepta todos los métodos que usamos
        configuration.setAllowedMethods(Arrays.asList("GET","POST","PUT","DELETE","OPTIONS"));
        
        // Acepta todas las cabeceras (incluyendo 'Authorization')
        configuration.setAllowedHeaders(Arrays.asList("*"));
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Aplica a TODAS las rutas
        return source;
    }
}