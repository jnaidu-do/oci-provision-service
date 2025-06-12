package main

import (
	"encoding/json"
	"fmt"
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
	h := handlers.NewHandler(ociClient)

	// Create router
	log.Printf("Setting up HTTP router")
	r := mux.NewRouter()

	// Add logging middleware
	r.Use(loggingMiddleware)

	// Health check endpoint
	r.HandleFunc("/health", healthCheckHandler).Methods(http.MethodGet)
	log.Printf("Registered health check endpoint at /health")

	// API v1 endpoints
	v1 := r.PathPrefix("/api/v1").Subrouter()
	v1.HandleFunc("/provision-baremetal", h.ProvisionBareMetal).Methods(http.MethodPost)
	v1.HandleFunc("/track-baremetal", h.TrackBareMetal).Methods(http.MethodGet)
	log.Printf("Registered API v1 endpoints")

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}
	addr := fmt.Sprintf(":%s", port)

	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
