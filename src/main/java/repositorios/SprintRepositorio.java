package repositorios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import entidades.SprintDAO;

import java.util.List;

@Repository
public interface SprintRepositorio extends JpaRepository<SprintDAO, Integer> {
    
    // Encontrar todos los sprints de un proyecto
    List<SprintDAO> findByProyectoId(Integer proyectoId);
}
