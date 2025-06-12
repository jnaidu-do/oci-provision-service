package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/jayanthnaidu/oci-provision-service/pkg/handlers"
	"github.com/jayanthnaidu/oci-provision-service/pkg/oci"
	"github.com/joho/godotenv"
)

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
}

// healthCheckHandler handles the health check endpoint
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// loggingMiddleware adds logging for all HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Incoming request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// Create a custom response writer to capture the status code
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		log.Printf("Request completed: %s %s - Status: %d - Duration: %v",
			r.Method, r.URL.Path, rw.statusCode, duration)
	})
}

// responseWriter is a custom response writer that captures the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found")
	}

	// Initialize OCI client
	log.Printf("Initializing OCI client")
	ociClient, err := oci.NewClient()
	if err != nil {
		log.Fatalf("Failed to initialize OCI client: %v", err)
	}

	// Initialize handlers
	log.Printf("Initializing HTTP handlers")
	h, err := handlers.NewHandler(ociClient)
	if err != nil {
		log.Fatalf("Failed to initialize handler: %v", err)
	}

	// Create router
	log.Printf("Setting up HTTP router")
	r := mux.NewRouter()

	// Add logging middleware
	r.Use(loggingMiddleware)

	// Health check endpoint
	r.HandleFunc("/health", healthCheckHandler).Methods(http.MethodGet)
	log.Printf("Added health check endpoint")

	// Provision bare metal endpoint
	r.HandleFunc("/api/v1/provision_baremetal", h.ProvisionBareMetal).Methods(http.MethodPost)
	log.Printf("Added provision bare metal endpoint")

	// Track bare metal endpoint
	r.HandleFunc("/api/v1/track_baremetal", h.TrackBareMetal).Methods(http.MethodGet)
	log.Printf("Added track bare metal endpoint")

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}
	log.Printf("Starting server on port %s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
