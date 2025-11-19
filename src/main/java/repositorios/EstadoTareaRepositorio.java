package repositorios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import entidades.EstadoTareaDAO;

import java.util.List;

@Repository
public interface EstadoTareaRepositorio extends JpaRepository<EstadoTareaDAO, Integer> {
    
    // Encontrar todos los estados de un proyecto
    List<EstadoTareaDAO> findByProyectoId(Integer proyectoId);
}
