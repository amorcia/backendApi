package entidades;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "TaskStatus")
public class EstadoTareaDAO {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "nombre")
    private String nombre;

    @Column(name = "proyecto_id")
    private Integer proyectoId;

    @Column(name = "color")
    private String color;

    @Column(name = "orden")
    private Integer orden;

    @Column(name = "es_estado_final")
    private Boolean esEstadoFinal;

    // --- Getters y Setters ---

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public Integer getProyectoId() {
        return proyectoId;
    }

    public void setProyectoId(Integer proyectoId) {
        this.proyectoId = proyectoId;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color;
    }

    public Integer getOrden() {
        return orden;
    }

    public void setOrden(Integer orden) {
        this.orden = orden;
    }

    public Boolean isEsEstadoFinal() {
        return esEstadoFinal;
    }

    public void setEsEstadoFinal(Boolean esEstadoFinal) {
        this.esEstadoFinal = esEstadoFinal;
    }
}
	