package router

import (
"log"
"net/http"
"context"

"neonschema/api"

	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// Initialize sets up the router with middleware and routes
func Initialize(privateDB *gorm.DB) *mux.Router {
	r := mux.NewRouter()

	// Example middleware
	r.Use(loggingMiddleware)
	// Add the private database to the context
	ctx := context.WithValue(context.Background(), dbContextKey{}, privateDB)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Store the private database in the request context
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	})
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
type dbContextKey struct{}

func RetrievePrivateDB(ctx context.Context) *gorm.DB {
	if db, ok := ctx.Value(dbContextKey{}).(*gorm.DB); ok {
		return db
	}
	log.Println("Private database not found in context")
	return nil
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

// NamedDBMiddleware attaches the named DB to the request context based on dbName in the URL
func NamedDBMiddleware(namedDatabases map[string]*gorm.DB) mux.MiddlewareFunc {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            vars := mux.Vars(r)
            dbName := vars["dbName"]
            db, ok := namedDatabases[dbName]
            if !ok {
                http.Error(w, "Database not found", http.StatusNotFound)
                return
            }
            ctx := context.WithValue(r.Context(), dbContextKey{}, db)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
