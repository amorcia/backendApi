	package config; // Asegúrate de que el paquete sea correcto
	
	import org.springframework.context.annotation.Bean;
	import org.springframework.context.annotation.Configuration;
	import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
	import org.springframework.security.crypto.password.PasswordEncoder;
	
	@Configuration
	public class AppConfig {
	
	    /**
	     * Define un Bean de PasswordEncoder que usa BCrypt.
	     * Spring ahora puede inyectar este objeto en cualquier
	     * clase que lo pida (como nuestro PruebaCrud).
	     */
	    @Bean
	    public PasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	    }
	}