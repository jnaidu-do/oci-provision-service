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
	log.Printf("Added health check endpoint at /health")

	// API routes
	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/provision_baremetal", h.ProvisionBareMetal).Methods(http.MethodPost)
	api.HandleFunc("/track_baremetal", h.TrackBareMetal).Methods(http.MethodGet)

	// Get port from environment variable or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	// Start server with simple configuration
	addr := fmt.Sprintf(":%s", port)
	log.Printf("Starting server on %s", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}
