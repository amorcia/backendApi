package repositorios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import entidades.NotificacionDAO;

import java.util.List;

@Repository
public interface NotificacionRepositorio extends JpaRepository<NotificacionDAO, Integer> {
    
    // Encontrar todas las notificaciones de un usuario
    List<NotificacionDAO> findByUsuarioId(Integer usuarioId);
}
