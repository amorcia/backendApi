package repositorios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import entidades.UsuarioDAO;

import java.util.Optional;

@Repository
public interface UsuarioRepositorio extends JpaRepository<UsuarioDAO, Integer> {
    
    // Podemos añadir métodos de búsqueda personalizados.
    // Spring Data JPA entenderá este nombre y creará la consulta por nosotros:
    // "SELECT * FROM User WHERE email = ?"
    Optional<UsuarioDAO> findByEmail(String email);
}
