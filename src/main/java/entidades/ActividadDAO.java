package entidades;

import java.time.LocalDateTime;

// NUEVOS IMPORTS
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;


@Entity
@Table(name = "Activity")
public class ActividadDAO {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id; 

    @Column(name = "usuario_id")
    private Integer usuarioId; 

    @Column(name = "tipo_accion")
    private String tipoAccion; 

    @Column(name = "entidad_tipo")
    private String entidadTipo; 

    @Column(name = "entidad_id")
    private Integer entidadId; 

    @Column(name = "descripcion")
    private String descripcion; 

    @JdbcTypeCode(SqlTypes.JSON) // Le dice a Hibernate que esto es un tipo JSON
    @Column(name = "datos_anteriores")
    private String datosAnteriores;

  
    @JdbcTypeCode(SqlTypes.JSON) // Le dice a Hibernate que esto es un tipo JSON
    @Column(name = "datos_nuevos")
    private String datosNuevos;

    @Column(name = "fecha_creacion")
    private LocalDateTime fechaCreacion; 

    
    // --- Getters y Setters ---
    
    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Integer getUsuarioId() {
        return usuarioId;
    }

    public void setUsuarioId(Integer usuarioId) {
        this.usuarioId = usuarioId;
    }

    public String getTipoAccion() {
        return tipoAccion;
    }

    public void setTipoAccion(String tipoAccion) {
        this.tipoAccion = tipoAccion;
    }

    public String getEntidadTipo() {
        return entidadTipo;
    }

    public void setEntidadTipo(String entidadTipo) {
        this.entidadTipo = entidadTipo;
    }

    public Integer getEntidadId() {
        return entidadId;
    }

    public void setEntidadId(Integer entidadId) {
        this.entidadId = entidadId;
    }

    public String getDescripcion() {
        return descripcion;
    }

    public void setDescripcion(String descripcion) {
        this.descripcion = descripcion;
    }

    public String getDatosAnteriores() {
        return datosAnteriores;
    }

    public void setDatosAnteriores(String datosAnteriores) {
        this.datosAnteriores = datosAnteriores;
    }

    public String getDatosNuevos() {
        return datosNuevos;
    }

    public void setDatosNuevos(String datosNuevos) {
        this.datosNuevos = datosNuevos;
    }

    public LocalDateTime getFechaCreacion() {
        return fechaCreacion;
    }

    public void setFechaCreacion(LocalDateTime fechaCreacion) {
        this.fechaCreacion = fechaCreacion;
    }
}