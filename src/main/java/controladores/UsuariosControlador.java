package controladores;

import java.util.List;
import java.util.Map;
import java.util.HashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize; 
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.DeleteMapping; 
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable; 
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping; 
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import dtos.RegistroUsuarioDTO; 
import dtos.UsuarioDTO;
import servicios.UsuariosServicio;

@RestController
public class UsuariosControlador {

    @Autowired
    private UsuariosServicio usuariosServicio;

    /**
     * GET /usuarios
     * (Añadida seguridad)
     */
    @GetMapping("/usuarios")
    @PreAuthorize("hasAnyAuthority('ROLE_1', 'ROLE_2')")
    public ResponseEntity<Map<String, Object>> getUsuariosData() {
        List<UsuarioDTO> usuarios = usuariosServicio.obtenerTodosLosUsuarios();
        Map<String, Object> respuesta = new HashMap<>();
        respuesta.put("listaDeUsuarios", usuarios); 
        return ResponseEntity.ok(respuesta);
    }

    /**
     * POST /usuarios
     * (Añadida seguridad)
     */
    @PostMapping("/usuarios")
    @PreAuthorize("hasAnyAuthority('ROLE_1', 'ROLE_2')")
    public ResponseEntity<?> registrarNuevoUsuario(@RequestBody RegistroUsuarioDTO datosRegistro) {
        try {
            // El servicio (modificado) se encarga de poner 'tsk006'
            UsuarioDTO nuevoUsuario = usuariosServicio.registrarNuevoUsuario(datosRegistro);
            return new ResponseEntity<>(nuevoUsuario, HttpStatus.CREATED);
        } catch (IllegalStateException e) {
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            e.printStackTrace(); // <-- Ayuda a depurar
            return new ResponseEntity<>(Map.of("error", "Error interno al registrar el usuario."), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * PUT /usuarios/{email}
     * (Añadida seguridad)
     */
    @PutMapping("/usuarios/{email}")
    @PreAuthorize("hasAnyAuthority('ROLE_1', 'ROLE_2')")
    public ResponseEntity<?> actualizarUsuario(@PathVariable String email, @RequestBody RegistroUsuarioDTO datosNuevos) {
        try {
            UsuarioDTO usuarioActualizado = usuariosServicio.actualizarUsuarioPorEmail(email, datosNuevos);
            return ResponseEntity.ok(usuarioActualizado);
        } catch (UsernameNotFoundException e) {
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.NOT_FOUND);
        } catch (IllegalStateException e) {
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            e.printStackTrace(); 
            return new ResponseEntity<>(Map.of("error", "Error interno al actualizar."), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * DELETE /usuarios/{email}
     * (Añadida seguridad y respuesta 200)
     */
    @DeleteMapping("/usuarios/{email}")
    @PreAuthorize("hasAnyAuthority('ROLE_1', 'ROLE_2')")
    public ResponseEntity<?> eliminarUsuario(@PathVariable String email) {
        try {
            usuariosServicio.eliminarUsuarioPorEmail(email); // Lógica de seguridad en el servicio
            return ResponseEntity.ok(Map.of("mensaje", "Usuario eliminado con éxito")); // 200 OK
        } catch (UsernameNotFoundException e) {
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.NOT_FOUND);
        } catch (IllegalStateException e) {
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.FORBIDDEN); // 403
        } catch (Exception e) {
            e.printStackTrace(); 
            return new ResponseEntity<>(Map.of("error", "Error interno al eliminar."), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    
    // ---
    // --- ¡NUEVO ENDPOINT PARA BORRADO MÚLTIPLE! ---
    // ---
    /**
     * POST /usuarios/delete-batch
     * Elimina una lista de usuarios por sus emails.
     */
    @PostMapping("/usuarios/delete-batch")
    @PreAuthorize("hasAnyAuthority('ROLE_1', 'ROLE_2')")
    public ResponseEntity<?> eliminarUsuariosBatch(@RequestBody List<String> emails) {
        try {
            // El servicio (modificado) itera y aplica la lógica de seguridad a cada uno
            usuariosServicio.eliminarUsuariosPorEmail(emails); 
            return ResponseEntity.ok(Map.of("mensaje", "Usuarios eliminados con éxito"));
        } catch (IllegalStateException e) {
            // Si el servicio lanza un error (ej: "Intentaste borrar un Owner")
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>(Map.of("error", "Error interno durante el borrado múltiple."), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}