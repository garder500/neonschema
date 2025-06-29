package main

import (
	"log"
	"net/http"
	"os"

	internal "neonschema/internal"
	database "neonschema/internal/database"

	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

var privateDB *gorm.DB

func init() {
	// Initialize the private database connection
	db, err := database.NewPrivateDB()
	if err != nil {
		log.Fatalf("Failed to initialize private database: %v", err)
	}
	privateDB = db.GetDB()
}

var NamedDatabases = make(map[string]*gorm.DB)

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found, using system environment variables")
	}
	// Initialize router
	r := internal.Initialize(privateDB)
	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port
	}
	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
