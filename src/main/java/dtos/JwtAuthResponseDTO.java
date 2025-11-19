package dtos;

// Este DTO ahora llevará el token, el rol, el email Y el flag de primer login
public class JwtAuthResponseDTO {
    
    private String accessToken;
    private String tokenType = "Bearer";
    private Integer rolId; // <-- ¡NECESITAMOS ESTE CAMPO!
    private String email; 
    private boolean necesitaCambiarClave;

    // --- CONSTRUCTOR NUEVO ---
    public JwtAuthResponseDTO(String accessToken, Integer rolId, String email, boolean necesitaCambiarClave) {
        this.accessToken = accessToken;
        this.rolId = rolId;
        this.email = email;
        this.necesitaCambiarClave = necesitaCambiarClave;
    }

    // --- Getters y Setters ---
    
    public String getAccessToken() {
        return accessToken;
    }
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
    public String getTokenType() {
        return tokenType;
    }
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
    public Integer getRolId() {
        return rolId;
    }
    public void setRolId(Integer rolId) {
        this.rolId = rolId;
    }
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }
    public boolean isNecesitaCambiarClave() {
        return necesitaCambiarClave;
    }
    public void setNecesitaCambiarClave(boolean necesitaCambiarClave) {
        this.necesitaCambiarClave = necesitaCambiarClave;
    }
}