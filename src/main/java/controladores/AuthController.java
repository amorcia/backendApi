package controladores;

import dtos.JwtAuthResponseDTO;
import dtos.LoginRequestDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication; 
import org.springframework.security.crypto.password.PasswordEncoder; 
import java.util.Optional; 
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime; // <-- Importar

import config.JwtTokenProvider;
import entidades.UsuarioDAO; 
import repositorios.UsuarioRepositorio; 

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenProvider tokenProvider;
    @Autowired
    private UsuarioRepositorio usuarioRepo; 
    @Autowired
    private PasswordEncoder passwordEncoder; 

    /**
     * POST /auth/login
     * (MODIFICADO para chequear primer login y sellar fecha de sesión)
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequestDTO loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginRequest.getEmail(),
                    loginRequest.getPassword()
                )
            );
            
            String email = loginRequest.getEmail();
            UsuarioDAO usuario = usuarioRepo.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado después de autenticar."));
            
            // --- LÓGICA DE PRIMER LOGIN ---
            // Asumimos que tu UsuarioDAO tiene un campo 'fechaUltimaSesion' (LocalDateTime)
            boolean necesitaCambiarClave = (usuario.getFechaUltimaSesion() == null);
            
            // Si NO es su primer login, actualizamos la fecha de sesión
            if (!necesitaCambiarClave) {
                usuario.setFechaUltimaSesion(LocalDateTime.now());
                usuarioRepo.save(usuario);
            }
            // --- FIN LÓGICA PRIMER LOGIN ---
            
            Integer rolId = usuario.getRolId();
            String jwt = tokenProvider.generateToken(authentication);

            // Devolvemos el DTO con el token, rolId, email Y el flag
            return ResponseEntity.ok(new JwtAuthResponseDTO(jwt, rolId, email, necesitaCambiarClave));
            
        } catch (Exception e) {
            return ResponseEntity.status(401)
                .body(Map.of("error", "Email o contraseña incorrectos."));
        }
    }

    /**
     * POST /auth/reset-password
     * (MODIFICADO para "sellar" la fecha de último login)
     */
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String nuevaPassword = request.get("nuevaPassword");
        
        if (email == null || nuevaPassword == null || email.isEmpty() || nuevaPassword.isEmpty()) {
            return ResponseEntity.status(400).body(Map.of("error", "Email y nueva contraseña son obligatorios."));
        }

        try {
            Optional<UsuarioDAO> usuarioOpt = usuarioRepo.findByEmail(email);
            
            if (usuarioOpt.isEmpty()) {
                return ResponseEntity.status(404).body(Map.of("error", "Usuario no encontrado."));
            }
            
            UsuarioDAO usuario = usuarioOpt.get();
            String passwordHasheada = passwordEncoder.encode(nuevaPassword);
            usuario.setPassword(passwordHasheada);
            
            // --- ¡IMPORTANTE! Sellamos la fecha de sesión ---
            // Al cambiar la contraseña (ya sea por primer login o por olvido),
            // "sellamos" la fecha para que no vuelva a pedirlo.
            usuario.setFechaUltimaSesion(LocalDateTime.now());
            // --- FIN DEL CAMBIO ---

            usuarioRepo.save(usuario);
            
            System.out.println("[API REAL] Contraseña cambiada con éxito para: " + email);
            
            return ResponseEntity.ok(Map.of("mensaje", "Contraseña cambiada con éxito"));

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "Error interno al cambiar la contraseña."));
        }
    }
    
    /**
     * POST /auth/forgot-password
     * (Simulación - Sin cambios)
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        System.out.println("[SIMULACIÓN] Petición de reseteo de contraseña para: " + email);
        return ResponseEntity.ok(Map.of("mensaje", "Código de reseteo enviado (simulación)"));
    }

    /**
     * POST /auth/verify-code
     * (Simulación - Sin cambios)
     */
    @PostMapping("/verify-code")
    public ResponseEntity<?> verifyCode(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String codigo = request.get("codigo");
        String CODIGO_SIMULADO = "123456"; 
        
        System.out.println("[SIMULACIÓN] Verificando código " + codigo + " para " + email);
        
        if (codigo != null && codigo.equals(CODIGO_SIMULADO)) {
            return ResponseEntity.ok(Map.of("mensaje", "Código verificado (simulación)"));
        } else {
            return ResponseEntity.status(400)
                .body(Map.of("error", "Código incorrecto (simulación)"));
        }
    }
}