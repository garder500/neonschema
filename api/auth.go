package api

import (
	"encoding/json"
"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// LoginRequest represents the structure of the login request payload
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginHandler handles user login and returns a JWT token
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.Username == "" || req.Password == "" {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Example: Validate username and password (replace with real validation)
	if req.Username != os.Getenv("ADMIN_USERNAME") || req.Password != os.Getenv("ADMIN_PASSWORD") {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": req.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

tokenString, err := token.SignedString(jwtSecret)
if err != nil {
log.Printf("Error signing token: %v", err)
http.Error(w, "Failed to generate token", http.StatusInternalServerError)
return
}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// JWTMiddleware validates the JWT token in the request
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
authHeader := r.Header.Get("Authorization")
if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
http.Error(w, "Missing or malformed token", http.StatusUnauthorized)
return
}
tokenString := authHeader[7:]

token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
log.Println("Unexpected signing method")
return nil, http.ErrAbortHandler
}
return jwtSecret, nil
})
if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
}

if err != nil {
http.Error(w, "Invalid token", http.StatusUnauthorized)
return
}

if !token.Valid {
http.Error(w, "Invalid token", http.StatusUnauthorized)
return
}

		next.ServeHTTP(w, r)
	})
}
