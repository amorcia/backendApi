package repositorios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import entidades.RolDAO;

import java.util.Optional;

@Repository
public interface RolRepositorio extends JpaRepository<RolDAO, Integer> {
    
    // Método para buscar un Rol por su nombre (Ej: "Admin")
    Optional<RolDAO> findByNombre(String nombre);
}