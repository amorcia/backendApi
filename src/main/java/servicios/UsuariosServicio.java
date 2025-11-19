package servicios;

import dtos.RegistroUsuarioDTO;
import dtos.UsuarioDTO;
import entidades.RolDAO;
import entidades.UsuarioDAO;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority; 
import org.springframework.security.core.authority.SimpleGrantedAuthority; 
import org.springframework.security.core.context.SecurityContextHolder; 
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import repositorios.RolRepositorio; 
import repositorios.UsuarioRepositorio;
import org.springframework.transaction.annotation.Transactional; 

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.Optional; 

@Service
public class UsuariosServicio implements UserDetailsService { 

    @Autowired
    private UsuarioRepositorio usuarioRepositorio;

    @Autowired
    private RolRepositorio rolRepositorio; // <- Necesario para buscar el rol por nombre

    @Autowired
    private PasswordEncoder passwordEncoder;

    // --- Lógica de Seguridad (Implementación de UserDetailsService) ---
    /**
     * Carga el usuario Y sus roles para Spring Security.
     * (Esta parte estaba bien)
     */
    @Override
    @Transactional(readOnly = true) 
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        
        UsuarioDAO usuarioDAO = usuarioRepositorio.findByEmail(email)
                .orElseThrow(() -> 
                    new UsernameNotFoundException("No se encontró un usuario con el email: " + email)
                );

        String rolId = usuarioDAO.getRolId().toString();
        
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + rolId)); // Ej: "ROLE_1", "ROLE_2"

        return new User(
            usuarioDAO.getEmail(),          // El "username"
            usuarioDAO.getPassword(),       // La contraseña YA HASHEADA de la BD
            authorities                     // ¡La lista de roles!
        );
    }

    // --- LÓGICA DE NEGOCIO (CRUD) ---

    /**
     * Obtiene todos los usuarios y los convierte a DTO.
     * (Esta parte estaba bien)
     */
    @Transactional(readOnly = true)
    public List<UsuarioDTO> obtenerTodosLosUsuarios() {
        return usuarioRepositorio.findAll()
                .stream()
                .map(this::convertirUsuarioA_DTO)
                .collect(Collectors.toList());
    }

    /**
     * (MODIFICADO)
     * Registra un nuevo usuario usando el 'rolNombre' del DTO.
     */
    @Transactional
    public UsuarioDTO registrarNuevoUsuario(RegistroUsuarioDTO datosRegistro) throws IllegalStateException {
        
        if (usuarioRepositorio.findByEmail(datosRegistro.getEmail()).isPresent()) {
            throw new IllegalStateException("El email " + datosRegistro.getEmail() + " ya está registrado.");
        }

        // --- ¡LÓGICA DE ROL POR NOMBRE! (NUEVO) ---
        String rolNombre = datosRegistro.getRolNombre();
        RolDAO rol = rolRepositorio.findByNombre(rolNombre) // Asumo que tienes findByNombre en RolRepositorio
            .orElseThrow(() -> new IllegalStateException("El rol '" + rolNombre + "' no existe."));
        // --- FIN LÓGICA DE ROL ---

        UsuarioDAO nuevoUsuario = new UsuarioDAO();
        nuevoUsuario.setNombre(datosRegistro.getNombre());
        nuevoUsuario.setEmail(datosRegistro.getEmail());
        nuevoUsuario.setActivo(datosRegistro.getActivo());
        nuevoUsuario.setFechaCreacion(LocalDateTime.now());
        
        // Asignamos el ID del rol que encontramos
        nuevoUsuario.setRolId(rol.getId()); 
        
        // Asignamos 'tsk006' hasheada
        nuevoUsuario.setPassword(passwordEncoder.encode("tsk006"));
        
        // Dejamos 'fechaUltimaSesion' como NULL para forzar el cambio
        nuevoUsuario.setFechaUltimaSesion(null);
        
        UsuarioDAO usuarioGuardado = usuarioRepositorio.save(nuevoUsuario);

        return convertirUsuarioA_DTO(usuarioGuardado);
    }

    /**
     * (MODIFICADO)
     * Actualiza un usuario Y APLICA REGLAS DE SEGURIDAD
     * para evitar escalada de privilegios.
     */
    @Transactional
    public UsuarioDTO actualizarUsuarioPorEmail(String emailOriginal, RegistroUsuarioDTO datosNuevos) throws UsernameNotFoundException, IllegalStateException {
        
        // 1. Encontrar al usuario que será modificado
        UsuarioDAO usuarioAActualizar = usuarioRepositorio.findByEmail(emailOriginal)
                .orElseThrow(() -> new UsernameNotFoundException("No se encontró usuario con email: " + emailOriginal));

        // 2. Validar que el nuevo email no esté en uso (si es que cambia)
        if (!emailOriginal.equals(datosNuevos.getEmail()) && usuarioRepositorio.findByEmail(datosNuevos.getEmail()).isPresent()) {
            throw new IllegalStateException("El nuevo email " + datosNuevos.getEmail() + " ya está en uso.");
        }

        // 3. --- ¡LÓGICA DE ROL POR NOMBRE! (NUEVO) ---
        String rolNombreNuevo = datosNuevos.getRolNombre();
        RolDAO rolNuevo = rolRepositorio.findByNombre(rolNombreNuevo)
            .orElseThrow(() -> new IllegalStateException("El rol '" + rolNombreNuevo + "' no existe."));
        Integer rolIdNuevo = rolNuevo.getId();
        // --- FIN LÓGICA DE ROL ---


        // 4. --- ¡SOLUCIÓN VULNERABILIDAD 1! (NUEVO) ---
        // Obtenemos el admin que está haciendo la petición
        String adminEmail = SecurityContextHolder.getContext().getAuthentication().getName();
        UsuarioDAO admin = usuarioRepositorio.findByEmail(adminEmail)
                .orElseThrow(() -> new IllegalStateException("No se pudo encontrar al administrador logueado."));

        // Regla 1: Un admin (rol 2) NO PUEDE modificar a un Owner (rol 1)
        if (usuarioAActualizar.getRolId() == 1 && admin.getRolId() != 1) {
            throw new IllegalStateException("Solo un Owner puede modificar a otro Owner.");
        }

        // Regla 2: Un admin (rol 2) NO PUEDE cambiar el rol de OTRO admin
        if (usuarioAActualizar.getRolId() == 2 && admin.getRolId() == 2 && !admin.getEmail().equals(usuarioAActualizar.getEmail())) {
             throw new IllegalStateException("Un Administrador no puede cambiar el rol de otro Administrador.");
        }
        
        // Regla 3: NADIE (ni admin ni owner) puede cambiar su PROPIO rol.
        if (admin.getEmail().equals(usuarioAActualizar.getEmail()) && !admin.getRolId().equals(rolIdNuevo)) {
            throw new IllegalStateException("No puedes cambiar tu propio rol. Pide a otro administrador que lo haga.");
        }
        // --- FIN DE LA SOLUCIÓN ---

        // 5. Actualizar los campos (ahora de forma segura)
        usuarioAActualizar.setNombre(datosNuevos.getNombre());
        usuarioAActualizar.setEmail(datosNuevos.getEmail());
        usuarioAActualizar.setActivo(datosNuevos.getActivo());
        usuarioAActualizar.setRolId(rolIdNuevo); // <- Se asigna el ID del rol nuevo

        // 6. Guardar y devolver DTO
        UsuarioDAO usuarioActualizado = usuarioRepositorio.save(usuarioAActualizar);
        return convertirUsuarioA_DTO(usuarioActualizado);
    }

    /**
     * Elimina un usuario por su email CON LÓGICA DE SEGURIDAD.
     * (Esta parte estaba bien)
     */
    @Transactional
    public void eliminarUsuarioPorEmail(String email) throws UsernameNotFoundException, IllegalStateException {
        
        String adminEmail = SecurityContextHolder.getContext().getAuthentication().getName();
        UsuarioDAO admin = usuarioRepositorio.findByEmail(adminEmail)
            .orElseThrow(() -> new IllegalStateException("No se pudo encontrar al administrador logueado."));

        UsuarioDAO usuario = usuarioRepositorio.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("No se encontró usuario con email: " + email));
        
        if (admin.getEmail().equals(usuario.getEmail())) {
            throw new IllegalStateException("No puedes borrarte a ti mismo.");
        }
        if (admin.getRolId() == 2 && (usuario.getRolId() == 1 || usuario.getRolId() == 2)) {
            throw new IllegalStateException("Un Administrador no puede borrar a un Owner u otro Administrador.");
        }
        
        usuarioRepositorio.delete(usuario);
    }
    
    /**
     * Elimina una lista de usuarios (para el borrado múltiple).
     * (Esta parte estaba bien)
     */
    @Transactional
    public void eliminarUsuariosPorEmail(List<String> emails) throws UsernameNotFoundException, IllegalStateException {
        for (String email : emails) {
            this.eliminarUsuarioPorEmail(email);
        }
    }


    // --- Método de Mapeo (Actualizado) ---
    /**
     * Convierte DAO a DTO.
     * (Esta parte estaba bien)
     */
    private UsuarioDTO convertirUsuarioA_DTO(UsuarioDAO entidad) {
        UsuarioDTO dto = new UsuarioDTO();
        
        dto.setNombre(entidad.getNombre());
        dto.setEmail(entidad.getEmail());
        dto.setAvatarUrl(entidad.getAvatarUrl());
        dto.setActivo(entidad.isActivo());
        dto.setFechaCreacion(entidad.getFechaCreacion());
        dto.setFechaUltimaSesion(entidad.getFechaUltimaSesion());

        String rolNombre = rolRepositorio.findById(entidad.getRolId())
                                      .map(RolDAO::getNombre)
                                      .orElse("N/A"); 
        dto.setRolNombre(rolNombre);
        
        dto.setRolId(entidad.getRolId());
        
        return dto;
    }
}