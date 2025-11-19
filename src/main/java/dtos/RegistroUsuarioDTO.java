package dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

// Este DTO se usa para CREAR y ACTUALIZAR usuarios.
public class RegistroUsuarioDTO {

    @NotEmpty(message = "El nombre no puede estar vacío")
    @Pattern(regexp = "^[a-zA-Z0-9 áéíóúÁÉÍÓÚñÑ]*$", message = "El nombre solo puede contener letras, números y espacios")
    private String nombre;

    @NotEmpty(message = "El email no puede estar vacío")
    @Email(message = "El formato del email no es válido")
    private String email;

    @NotNull(message = "Debe indicar si el usuario está activo")
    private Boolean activo;

    // --- ¡ESTE ES EL CAMBIO IMPORTANTE! ---
    // Ya no pedimos 'rolId'. Pedimos 'rolNombre'.
    @NotEmpty(message = "El nombre del rol no puede estar vacío")
    private String rolNombre; 
    // --- FIN DEL CAMBIO ---

    
    // --- Getters y Setters ---

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

    public Boolean getActivo() {
        return activo;
    }
    public void setActivo(Boolean activo) {
        this.activo = activo;
    }

    // --- Getter y Setter para el nuevo campo ---
    public String getRolNombre() {
        return rolNombre;
    }
    public void setRolNombre(String rolNombre) {
        this.rolNombre = rolNombre;
    }
}