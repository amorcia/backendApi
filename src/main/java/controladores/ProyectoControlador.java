package controladores;

import java.util.List;
import java.util.Map; 
import java.util.HashMap; 

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import dtos.ProyectoDTO; // <-- Importa el DTO de Proyecto
import servicios.ProyectoServicio; // <-- Importa el Servicio de Proyecto

/**
 * Controlador REST para la API de Proyectos.
 * 1. Anotado con @RestController para devolver JSON.
 * 2. Inyecta el servicio de lógica (`ProyectoServicio`).
 */
@RestController
public class ProyectoControlador {

    @Autowired
    private ProyectoServicio proyecto; // <-- Inyecta el servicio de Proyecto

    /**
     * Gestiona la petición a la API de proyectos.
     * URL: /taskflow/v1/proyectos
     * Devuelve un objeto JSON con la lista de proyectos.
     */
    @GetMapping("/proyectos") // <-- Endpoint lógico para proyectos
    public Map<String, Object> getProyectosData() {

        // 1. Pedimos los datos al servicio
        List<ProyectoDTO> proyectos = proyecto.obtenerTodosLosProyectos();

        // 2. Creamos un "contenedor" (Map) para los datos
        Map<String, Object> respuesta = new HashMap<>();
        
        // 3. Añadimos los datos al Map
        respuesta.put("listaDeProyectos", proyectos); // <-- Añade la lista de proyectos

        // 4. Devolvemos el Map (Spring lo convierte en JSON)
        return respuesta;
    }
}