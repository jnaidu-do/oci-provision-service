package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/jayanthnaidu/oci-provision-service/pkg/handlers"
	"github.com/jayanthnaidu/oci-provision-service/pkg/oci"
)

func main() {
	// Initialize OCI client
	ociClient, err := oci.NewClient()
	if err != nil {
		log.Fatalf("Failed to initialize OCI client: %v", err)
	}

	// Initialize handlers
	h := handlers.NewHandler(ociClient)

	// Create router
	r := mux.NewRouter()

	// API routes
	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/provision_baremetal", h.ProvisionBareMetal).Methods(http.MethodPost)
	api.HandleFunc("/track_baremetal", h.TrackBareMetal).Methods(http.MethodGet)

	// Get port from environment variable or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	// Start server
	addr := fmt.Sprintf(":%s", port)
	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
