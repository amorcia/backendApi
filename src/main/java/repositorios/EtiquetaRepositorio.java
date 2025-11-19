package repositorios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import entidades.EtiquetaDAO;

import java.util.List;

@Repository
public interface EtiquetaRepositorio extends JpaRepository<EtiquetaDAO, Integer> {
    
    List<EtiquetaDAO> findByProyectoId(Integer proyectoId);
}
