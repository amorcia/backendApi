# Usa una imagen base con Java 21
FROM eclipse-temurin:21-jdk-alpine

# El volumen de trabajo donde se copia el JAR
WORKDIR /app

# Copia el JAR generado por Maven
COPY target/taskflow_solutions-1.0.jar app.jar

# Expone el puerto por defecto de Spring Boot
EXPOSE 8080

# Comando para ejecutar la aplicación
ENTRYPOINT ["java", "-jar", "app.jar"]