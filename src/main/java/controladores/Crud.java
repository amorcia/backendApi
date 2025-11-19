package controladores;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

// Quitamos la importación de RolDAO y RolRepositorio
// import entidades.RolDAO; 
import entidades.UsuarioDAO;
// import repositorios.RolRepositorio;
import repositorios.UsuarioRepositorio;
import java.time.LocalDateTime;

@Component
@Transactional
public class Crud implements CommandLineRunner {

    // Ya no necesitamos el repositorio de Roles aquí
    // @Autowired
    // private RolRepositorio rolRepo; 
    
    @Autowired
    private UsuarioRepositorio usuarioRepo;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        System.out.println("\n--- [PruebaCrudRunner]: Verificando datos iniciales... ---");

        // --- Mantenemos la lógica de verificación ---
        if (usuarioRepo.findByEmail("admin@taskflow.com").isPresent()) {
            System.out.println("El usuario 'admin' ya existe. Omitiendo creación de datos iniciales.");
        } else {
            // Si no existe, creamos solo el usuario
            crearUsuarioAdminInicial();
        }
        
        System.out.println("--- [PruebaCrudRunner]: Finalizado. El servidor web sigue corriendo. ---");
    }

    /**
     * Método privado para crear SOLO el usuario admin.
     * Asume que el Rol ID=2 (Admin) ya existe en la BBDD.
     */
    private void crearUsuarioAdminInicial() {
        System.out.println("Creando nuevo usuario 'admin' inicial...");
        try {
            // --- 1. CREAR ROL (LÓGICA ELIMINADA) ---
            // Asumimos que los roles 1 (Owner) y 2 (Admin) ya existen.
            
            // Definimos el ID del rol "Admin" según tu nueva lista
            Integer adminRolId = 2;

            // --- 2. CREAR USUARIO ADMIN ---
            UsuarioDAO nuevoUsuario = new UsuarioDAO();
            nuevoUsuario.setNombre("admin");
            nuevoUsuario.setEmail("admin@taskflow.com");
            nuevoUsuario.setActivo(true);
            nuevoUsuario.setRolId(adminRolId); // <-- Usamos el ID fijo
            nuevoUsuario.setFechaCreacion(LocalDateTime.now());
            
            // Codificamos la contraseña
            String passwordPlana = "tsk006";
            String passwordHasheada = passwordEncoder.encode(passwordPlana);
            nuevoUsuario.setPassword(passwordHasheada);
            
            usuarioRepo.save(nuevoUsuario);
            System.out.println("Usuario 'admin' (con RolID=2) creado."); // <-- ID Ocultado
            
            System.out.println("\n--- [PruebaCrudRunner]: USUARIO INICIAL CREADO CON ÉXITO ---");

        } catch (Exception e) {
            System.err.println("\n--- [PruebaCrudRunner]: ERROR AL INSERTAR USUARIO INICIAL ---");
            e.printStackTrace();
        }
    }
}