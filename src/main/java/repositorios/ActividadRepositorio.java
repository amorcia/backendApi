package repositorios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import entidades.ActividadDAO;

import java.util.List;

@Repository
public interface ActividadRepositorio extends JpaRepository<ActividadDAO, Integer> {
    
    List<ActividadDAO> findByUsuarioId(Integer usuarioId);
}
