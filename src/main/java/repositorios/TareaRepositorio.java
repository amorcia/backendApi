package repositorios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import entidades.TareaDAO;

import java.util.List;

@Repository
public interface TareaRepositorio extends JpaRepository<TareaDAO, Integer> {
    
    // Búsquedas personalizadas comunes para Tareas:
    List<TareaDAO> findByProyectoId(Integer proyectoId);
    List<TareaDAO> findByEstadoId(Integer estadoId);
    List<TareaDAO> findByCreadorId(Integer creadorId);
    List<TareaDAO> findBySprintId(Integer sprintId);
}
