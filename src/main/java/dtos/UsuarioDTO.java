package dtos;

import java.time.LocalDateTime;

// DTO para MOSTRAR un usuario.
public class UsuarioDTO {

    private String nombre;
    private String email;
    private String avatarUrl;
    
    // --- ¡CAMBIO IMPORTANTE! ---
    // 'rolNombre' es para mostrar (Ej: "Admin")
    private String rolNombre; 
    // 'rolId' es para la lógica de seguridad (Ej: 2)
    private Integer rolId; // <-- AÑADIDO
    // --- FIN CAMBIO ---

    private LocalDateTime fechaCreacion;
    private LocalDateTime fechaUltimaSesion;
    private Boolean activo;
    
    // Constructor vacío (para Jackson)
    public UsuarioDTO() {}
    
    // Constructor (si tu servicio lo usa para mapear)
    public UsuarioDTO(
        String nombre, String email, String avatarUrl, 
        String rolNombre, Integer rolId, // <-- AÑADIDO
        LocalDateTime fechaCreacion, LocalDateTime fechaUltimaSesion, Boolean activo) 
    {
        this.nombre = nombre;
        this.email = email;
        this.avatarUrl = avatarUrl;
        this.rolNombre = rolNombre;
        this.rolId = rolId; // <-- AÑADIDO
        this.fechaCreacion = fechaCreacion;
        this.fechaUltimaSesion = fechaUltimaSesion;
        this.activo = activo;
    }


    // --- Getters y Setters (Actualizados) ---

    public String getNombre() {
        return nombre;
    }
    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }

    public String getAvatarUrl() {
        return avatarUrl;
    }
    public void setAvatarUrl(String avatarUrl) {
        this.avatarUrl = avatarUrl;
    }

    public String getRolNombre() {
        return rolNombre;
    }
    public void setRolNombre(String rolNombre) {
        this.rolNombre = rolNombre;
    }
    
    // --- CAMBIO ---
    public Integer getRolId() {
        return rolId;
    }
    public void setRolId(Integer rolId) {
        this.rolId = rolId;
    }
    // --- FIN CAMBIO ---

    public LocalDateTime getFechaCreacion() {
        return fechaCreacion;
    }
    public void setFechaCreacion(LocalDateTime fechaCreacion) {
        this.fechaCreacion = fechaCreacion;
    }

    public LocalDateTime getFechaUltimaSesion() {
        return fechaUltimaSesion;
    }
    public void setFechaUltimaSesion(LocalDateTime fechaUltimaSesion) {
        this.fechaUltimaSesion = fechaUltimaSesion;
    }

    public Boolean getActivo() {
        return activo;
    }
    public void setActivo(Boolean activo) {
        this.activo = activo;
    }
}