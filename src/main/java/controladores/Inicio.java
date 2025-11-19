package controladores;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan; // Import MUY importante
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * Clase principal que arranca la aplicacion Spring Boot.
 *
 * ANOTACIONES CLAVE:
 * 1. @SpringBootApplication: Inicia la auto-configuracion de Spring.
 * Por defecto, solo escanea su propio paquete (controladores) y sub-paquetes.
 *
 * 2. @ComponentScan: Le FORZAMOS a escanear los paquetes "hermanos"
 * donde estan nuestros @Service y @Repository, que de otra forma
 * Spring no encontraria.
 */
@SpringBootApplication
@ComponentScan(basePackages = {"controladores", "servicios", "repositorios","config"})
@EntityScan(basePackages = "entidades")
@EnableJpaRepositories(basePackages = "repositorios")
public class Inicio {

    public static void main(String[] args) {
        System.out.println("--- [Inicio] Arrancando TaskFlow Solutions (MODO SERVIDOR WEB) ---");

        // --- MODO SERVIDOR WEB (para probar el Dashboard) ---
        // 1. Creamos la aplicacion
        SpringApplication app = new SpringApplication(Inicio.class);

        // 2. (IMPORTANTE) Comentamos esta linea para que arranque el servidor Tomcat.
        // Si la descomentas, se ejecutara en modo consola (como el PruebaCrud)
        // y se cerrara solo al terminar.
        //
        // app.setWebApplicationType(WebApplicationType.NONE);

        // 3. Ejecutamos la aplicacion (esto inicia el servidor y lo mantiene vivo)
        app.run(args);

        System.out.println("--- [Inicio] Servidor web iniciado. Listo para recibir peticiones. ---");
    }
}

