package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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

// healthCheckHandler handles health check requests
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
	log.Println("Starting application...")

	// Load environment variables
	log.Println("Loading environment variables...")
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
		log.Fatalf("Failed to initialize handlers: %v", err)
	}

	// Create router
	log.Printf("Setting up HTTP router")
	r := mux.NewRouter()

	// Add logging middleware
	log.Printf("Adding logging middleware")
	r.Use(loggingMiddleware)

	// Health check endpoint
	log.Printf("Setting up health check endpoint")
	r.HandleFunc("/health", healthCheckHandler).Methods(http.MethodGet)

	// API endpoints
	log.Printf("Setting up API endpoints")
	r.HandleFunc("/api/v1/provision-baremetal", h.ProvisionBareMetal).Methods(http.MethodPost)
	r.HandleFunc("/api/v1/track-baremetal", h.TrackBareMetal).Methods(http.MethodGet)

	// Create server
	log.Printf("Creating HTTP server")
	srv := &http.Server{
		Addr:         ":5000",
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine
	log.Printf("Starting server on port 5000...")
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	log.Printf("Waiting for interrupt signal...")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Create shutdown context with timeout
	log.Printf("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Printf("Server exited properly")
}
