package repositorios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import entidades.ProyectoDAO;

import java.util.List;

@Repository
public interface ProyectoRepositorio extends JpaRepository<ProyectoDAO, Integer> {
    
    // Ejemplo de búsqueda personalizada:
    // Encontrar todos los proyectos de un equipo
    List<ProyectoDAO> findByEquipoId(Integer equipoId);

    // Encontrar todos los proyectos de un creador
    List<ProyectoDAO> findByCreadorId(Integer creadorId);
}
