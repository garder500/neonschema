package router

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"neonschem/api"
)

// Initialize sets up the router with middleware and routes
func Initialize() *mux.Router {
	r := mux.NewRouter()

	// Example middleware
	r.Use(loggingMiddleware)

	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/login", api.LoginHandler).Methods("POST")

	// Protect routes with JWT middleware
	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(api.JWTMiddleware)
	protected.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This is a protected route"))
	}).Methods("GET")

	return r
}

// loggingMiddleware is an example middleware for logging requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the request
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// healthHandler is an example handler for a health check endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
