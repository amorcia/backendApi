package servicios;

import dtos.ProyectoDTO;
import entidades.ProyectoDAO;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import repositorios.ProyectoRepositorio;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Servicio de lógica de negocio para la entidad Proyecto.
 * Se encarga de la lógica y la conversión de DAO a DTO.
 */
@Service
public class ProyectoServicio {

    @Autowired
    private ProyectoRepositorio proyectoRepositorio;

    /**
     * Obtiene todos los proyectos y los convierte a DTO.
     */
    public List<ProyectoDTO> obtenerTodosLosProyectos() {
        return proyectoRepositorio.findAll()
                .stream()
                .map(this::convertirProyectoA_DTO)
                .collect(Collectors.toList());
    }

    // --- Métodos Privados de Mapeo (Conversión) ---

    private ProyectoDTO convertirProyectoA_DTO(ProyectoDAO entidad) {
        ProyectoDTO dto = new ProyectoDTO();
        
        dto.setNombre(entidad.getNombre());
        dto.setDescripcion(entidad.getDescripcion());
        dto.setTipo(entidad.getTipo());
        dto.setColor(entidad.getColor());
        dto.setFechaInicio(entidad.getFechaInicio());
        dto.setFechaFin(entidad.getFechaFin());
        dto.setEstado(entidad.getEstado());
        dto.setProgreso(entidad.getProgreso());
        return dto;
    }
}