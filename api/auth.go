package api

import (
	"context"
	"encoding/json"
	"log"

	"neonschema/internal/database"
	"neonschema/internal/utils"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// LoginRequest represents the structure of the login request payload
type LoginRequest struct {
	Username          string `json:"username"`
	Password          string `json:"password"`
	OptionalProjectID string `json:"optional_project_id,omitempty"` // Optional project ID for user login
}

type SimplifiedUser struct {
	Username string `json:"username"`
	Iad      uint   `json:"iad"` // User ID
	Role     string `json:"role"`
	Project  string `json:"project"`
}

type SimplifiedUserKey struct{}

// LoginHandler handles user login and returns a JWT token
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.Username == "" || req.Password == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "Invalid request payload", utils.ErrorDetails{
			Code:    "invalid_request_payload",
			Message: "The request payload is invalid or missing required fields",
		})
		return
	}

	// we need to find out if we are either logging in as a superadmin or a regular user

	if req.Username != os.Getenv("ADMIN_USERNAME") || req.Password != os.Getenv("ADMIN_PASSWORD") {
		// Ok, maybe we are a regular user
		privateDB := database.RetrievePrivateDB(r.Context())

		if privateDB == nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "Database connection error", utils.ErrorDetails{
				Code:    "db_connection_error",
				Message: "Failed to connect to the database",
			})
			return
		}

		var user database.Users
		// We only know the username right now, so we will try to find the user by username
		if err := privateDB.Where("username = ?", req.Username).First(&user).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				utils.WriteErrorResponse(w, http.StatusUnauthorized, "Invalid credentials", utils.ErrorDetails{
					Code:    "invalid_credentials",
					Message: "The provided username or password is incorrect",
				})
				return
			}
			log.Printf("Error retrieving user: %v", err)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "Database error", utils.ErrorDetails{
				Code:    "db_error",
				Message: "An error occurred while accessing the database",
			})
			return
		}

		// We got the user ? Now we need to see if the password Hashes match
		if !user.CheckPassword(req.Password) {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "Invalid credentials", utils.ErrorDetails{
				Code:    "invalid_credentials",
				Message: "The provided username or password is incorrect",
			})
			return
		}

		// Does this user used an optional project ID?
		if req.OptionalProjectID != "" {
			// Check if the user is part of the project
			var project database.Project
			if err := privateDB.Where("id = ? AND owner_id = ?", req.OptionalProjectID, user.ID).First(&project).Error; err != nil {
				if err == gorm.ErrRecordNotFound {
					utils.WriteErrorResponse(w, http.StatusForbidden, "Access denied", utils.ErrorDetails{
						Code:    "access_denied",
						Message: "You do not have access to this project",
					})
					return
				}
				log.Printf("Error retrieving project: %v", err)
				utils.WriteErrorResponse(w, http.StatusInternalServerError, "Database error", utils.ErrorDetails{
					Code:    "db_error",
					Message: "An error occurred while accessing the database",
				})
				return
			}
			// If the project exists and the user is part of it, we can proceed
			log.Printf("User %s is part of project %s", user.Username, project.Name)
			// Generate JWT token for regular user with project context
			if jwtSecret == nil {
				utils.WriteErrorResponse(w, http.StatusInternalServerError, "JWT secret not set", utils.ErrorDetails{
					Code:    "jwt_secret_not_set",
					Message: "The JWT secret is not set in the environment variables",
				})
				return
			}
			// Generate JWT token for regular user with project context
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"username": user.Username,
				"role":     user.Role,
				"project":  project.ID, // Use the project name or ID as needed
				"exp":      time.Now().Add(time.Hour * 24).Unix(),
			})
			tokenString, err := token.SignedString(jwtSecret)
			if err != nil {
				log.Printf("Error signing token: %v", err)
				utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to generate token", utils.ErrorDetails{
					Code:    "token_generation_error",
					Message: "An error occurred while generating the token",
				})
				return
			}
			utils.WriteJSONResponse(w, http.StatusOK, map[string]string{"token": tokenString})
			return
		}

		// Generate JWT token for regular user
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": user.Username,
			"iad":      user.ID, // Include user ID in the token for reference
			"role":     user.Role,
			"project":  "root", // Default project if not specified
			// "project":  req.OptionalProjectID, // Use the optional project ID if provided
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		})
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			log.Printf("Error signing token: %v", err)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to generate token", utils.ErrorDetails{
				Code:    "token_generation_error",
				Message: "An error occurred while generating the token",
			})
			return
		}
		utils.WriteJSONResponse(w, http.StatusOK, map[string]string{"token": tokenString})
		return
	} else {
		// Ok, we are a superadmin, so we will generate a token for the superadmin
		log.Println("Superadmin login successful")
		if jwtSecret == nil {
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "JWT secret not set", utils.ErrorDetails{
				Code:    "jwt_secret_not_set",
				Message: "The JWT secret is not set in the environment variables",
			})
			return
		}
		// Generate JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": req.Username,
			"iad":      0, // Superadmin ID can be set to 0 or a specific ID if needed
			"role":     "superadmin",
			"project":  "root", // Root give access to all projects
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		})

		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			log.Printf("Error signing token: %v", err)
			utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to generate token", utils.ErrorDetails{
				Code:    "token_generation_error",
				Message: "An error occurred while generating the token",
			})
			return
		}

		utils.WriteJSONResponse(w, http.StatusOK, map[string]string{"token": tokenString})
	}

}

// JWTMiddleware validates the JWT token in the request
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "Missing or malformed token", utils.ErrorDetails{
				Code:    "missing_token",
				Message: "Authorization header is missing or malformed",
			})
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

		if err != nil || !token.Valid {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "Invalid token", utils.ErrorDetails{
				Code:    "invalid_token",
				Message: "The provided token is invalid",
			})
			return
		}

		// Extract claims and add to context
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			utils.WriteErrorResponse(w, http.StatusUnauthorized, "Invalid token claims", utils.ErrorDetails{
				Code:    "invalid_claims",
				Message: "Token claims are invalid",
			})
			return
		}

		username, _ := claims["username"].(string)
		role, _ := claims["role"].(string)

		project, _ := claims["project"].(string)
		if project == "" {
			project = "root" // Default to root project if not specified
		}
		ctx := r.Context()
		ctx = context.WithValue(ctx, SimplifiedUserKey{}, SimplifiedUser{
			Username: username,
			Iad:      uint(claims["iad"].(float64)), // Convert float64 to uint
			Role:     role,
			Project:  project,
		})

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
