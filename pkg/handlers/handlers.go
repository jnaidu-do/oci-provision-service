package handlers

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/jayanthnaidu/oci-provision-service/pkg/oci"
	"golang.org/x/crypto/ssh"
)

// Handler represents the HTTP handlers for the API
type Handler struct {
	ociClient *oci.Client
}

// NewHandler creates a new handler instance
func NewHandler(ociClient *oci.Client) *Handler {
	return &Handler{
		ociClient: ociClient,
	}
}

// ProvisionRequest represents the new request format
type ProvisionRequest struct {
	CloudProvider  string `json:"cloudProvider"`
	Operation      string `json:"operation"`
	Region         string `json:"region"`
	NumHypervisors int    `json:"num_hypervisors"`
	RegionID       string `json:"regionId"`
}

// ProvisionResponse represents the response format
type ProvisionResponse struct {
	Status               string `json:"status"`
	InstanceTasksStarted int    `json:"instance_tasks_started"`
}

// ProvisionedInstanceDetails represents the details of a provisioned instance
type ProvisionedInstanceDetails struct {
	InstanceID     string `json:"instance_id"`
	PrivateIP      string `json:"private_ip"`
	LifecycleState string `json:"lifecycle_state"`
	DisplayName    string `json:"display_name"`
}

// ProvisioningEvent represents the event logged when an instance is running
type ProvisioningEvent struct {
	CloudProvider              string                     `json:"cloudProvider"`
	Operation                  string                     `json:"operation"`
	Region                     string                     `json:"region"`
	NumHypervisors             int                        `json:"num_hypervisors"`
	RegionID                   string                     `json:"regionId"`
	ProvisionedInstanceDetails ProvisionedInstanceDetails `json:"provisioned_instance_details"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// convertPEMToSSHPublicKey converts a PEM private key to SSH public key format
func convertPEMToSSHPublicKey(pemKey string) (string, error) {
	// Decode the PEM block
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	var privateKey *rsa.PrivateKey
	var err error

	// Try PKCS1 format first
	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse private key: %v", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("private key is not RSA")
		}
	}

	// Create SSH public key
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to create SSH public key: %v", err)
	}

	// Return the authorized key format
	return string(ssh.MarshalAuthorizedKey(publicKey)), nil
}

// generateRandomSuffix generates a random 8-character hex string
func generateRandomSuffix() (string, error) {
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ProvisionBareMetal handles the POST /api/v1/provision_baremetal endpoint
func (h *Handler) ProvisionBareMetal(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received provision request from %s", r.RemoteAddr)

	var req ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.CloudProvider == "" || req.Operation == "" || req.Region == "" || req.RegionID == "" {
		log.Printf("Missing required fields in request")
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if req.NumHypervisors <= 0 {
		log.Printf("Invalid num_hypervisors value: %d", req.NumHypervisors)
		http.Error(w, "num_hypervisors must be greater than 0", http.StatusBadRequest)
		return
	}

	// Get OCI configuration from environment
	config := oci.InstanceConfig{
		CompartmentID:      os.Getenv("OCI_COMPARTMENT_ID"),
		AvailabilityDomain: os.Getenv("OCI_AVAILABILITY_DOMAIN"),
		ImageID:            os.Getenv("OCI_IMAGE_ID"),
		SubnetID:           os.Getenv("OCI_SUBNET_ID"),
		PEMPrivateKey:      os.Getenv("OCI_PEM_PRIVATE_KEY"),
	}

	// Validate OCI configuration
	if config.CompartmentID == "" || config.AvailabilityDomain == "" ||
		config.ImageID == "" || config.SubnetID == "" || config.PEMPrivateKey == "" {
		log.Printf("Missing OCI configuration")
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	// Create a wait group to track all provisioning tasks
	var wg sync.WaitGroup
	errorChan := make(chan error, req.NumHypervisors)

	// Launch instances concurrently
	for i := 0; i < req.NumHypervisors; i++ {
		wg.Add(1)
		go func(instanceNum int) {
			defer wg.Done()

			// Generate random suffix
			randomSuffix, err := generateRandomSuffix()
			if err != nil {
				log.Printf("Error generating random suffix: %v", err)
				errorChan <- err
				return
			}

			// Generate unique display name with random suffix
			config.DisplayName = fmt.Sprintf("baremetal-instance-%d-%s", instanceNum+1, randomSuffix)
			log.Printf("Generated display name: %s", config.DisplayName)

			// Launch instance
			instance, err := h.ociClient.LaunchBareMetalInstance(config)
			if err != nil {
				log.Printf("Error launching instance %s: %v", config.DisplayName, err)
				errorChan <- err
				return
			}

			// Start background polling
			go h.pollInstanceStatus(r.Context(), instance.ID, req, config.DisplayName)
		}(i)
	}

	// Wait for all launch operations to complete
	wg.Wait()
	close(errorChan)

	// Check if any errors occurred
	for err := range errorChan {
		if err != nil {
			log.Printf("Error during batch provisioning: %v", err)
			http.Error(w, "Failed to provision instances", http.StatusInternalServerError)
			return
		}
	}

	// Send success response
	response := ProvisionResponse{
		Status:               fmt.Sprintf("Initiated provisioning for %d bare metal instance(s)", req.NumHypervisors),
		InstanceTasksStarted: req.NumHypervisors,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
}

// pollInstanceStatus polls the instance status and logs when running
func (h *Handler) pollInstanceStatus(ctx context.Context, instanceID string, req ProvisionRequest, displayName string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Context cancelled for instance %s", instanceID)
			return
		case <-ticker.C:
			instance, err := h.ociClient.GetInstance(instanceID)
			if err != nil {
				log.Printf("Error getting instance %s status: %v", instanceID, err)
				continue
			}

			if instance.LifecycleState == "RUNNING" {
				// Create event
				event := ProvisioningEvent{
					CloudProvider:  req.CloudProvider,
					Operation:      req.Operation,
					Region:         req.Region,
					NumHypervisors: req.NumHypervisors,
					RegionID:       req.RegionID,
					ProvisionedInstanceDetails: ProvisionedInstanceDetails{
						InstanceID:     instanceID,
						PrivateIP:      instance.PrivateIP,
						LifecycleState: instance.LifecycleState,
						DisplayName:    displayName,
					},
				}

				// Log the event
				eventJSON, _ := json.Marshal(event)
				log.Printf("Instance %s is now running: %s", instanceID, string(eventJSON))
				return
			}

			log.Printf("Instance %s status: %s", instanceID, instance.LifecycleState)
		}
	}
}

// TrackBareMetal handles the GET /api/v1/track_baremetal endpoint
func (h *Handler) TrackBareMetal(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request to track instance from %s", r.RemoteAddr)

	instanceID := r.URL.Query().Get("instance_id")
	if instanceID == "" {
		log.Printf("Missing instance_id in request")
		sendError(w, http.StatusBadRequest, "Missing instance_id query parameter")
		return
	}
	log.Printf("Tracking instance: %s", instanceID)

	instance, err := h.ociClient.GetInstance(instanceID)
	if err != nil {
		log.Printf("Error getting instance %s: %v", instanceID, err)
		sendError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get instance: %v", err))
		return
	}

	if instance == nil {
		log.Printf("Instance %s not found", instanceID)
		sendError(w, http.StatusNotFound, fmt.Sprintf("Instance with ID '%s' not found", instanceID))
		return
	}

	log.Printf("Found instance %s with state: %s", instanceID, instance.LifecycleState)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ProvisionedInstanceDetails{
		InstanceID:     instance.ID,
		PrivateIP:      instance.PrivateIP,
		LifecycleState: instance.LifecycleState,
	})
	log.Printf("Sent response for instance %s", instanceID)
}

// sendError sends an error response with the given status code and message
func sendError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error: message,
	})
}
