package repositorios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import entidades.AdjuntoDAO;

import java.util.List;

@Repository
public interface AdjuntoRepositorio extends JpaRepository<AdjuntoDAO, Integer> {
    
    List<AdjuntoDAO> findByTareaId(Integer tareaId);
    List<AdjuntoDAO> findByComentarioId(Integer comentarioId);
}
