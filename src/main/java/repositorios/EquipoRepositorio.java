package repositorios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import entidades.EquipoDAO;

@Repository
public interface EquipoRepositorio extends JpaRepository<EquipoDAO, Integer> {
    // Métodos automáticos: save(), findById(), findAll(), deleteById()...
}
