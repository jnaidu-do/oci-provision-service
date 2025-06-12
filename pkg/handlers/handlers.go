package handlers

import (
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
	Message    string `json:"message"`
	InstanceID string `json:"instance_id"`
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

	// Validate request
	if req.CloudProvider != "oci" {
		http.Error(w, "Only OCI cloud provider is supported", http.StatusBadRequest)
		return
	}

	if req.Operation != "provision" {
		http.Error(w, "Only provision operation is supported", http.StatusBadRequest)
		return
	}

	if req.NumHypervisors <= 0 {
		http.Error(w, "Number of hypervisors must be greater than 0", http.StatusBadRequest)
		return
	}

	// Generate a unique display name for each instance
	randomSuffix, err := generateRandomSuffix()
	if err != nil {
		log.Printf("Error generating random suffix: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	displayName := fmt.Sprintf("baremetal-instance-%d-%s", 1, randomSuffix)
	log.Printf("Generated display name: %s", displayName)

	// Launch the instance
	instance, err := h.ociClient.LaunchBareMetalInstance(oci.InstanceConfig{
		CompartmentID:      os.Getenv("OCI_COMPARTMENT_ID"),
		AvailabilityDomain: os.Getenv("OCI_AVAILABILITY_DOMAIN"),
		ImageID:            os.Getenv("OCI_IMAGE_ID"),
		SubnetID:           os.Getenv("OCI_SUBNET_ID"),
		PEMPrivateKey:      os.Getenv("OCI_PEM_PRIVATE_KEY"),
		DisplayName:        displayName,
	})
	if err != nil {
		log.Printf("Error launching instance %s: %v", displayName, err)
		http.Error(w, fmt.Sprintf("Error during batch provisioning: %v", err), http.StatusInternalServerError)
		return
	}

	// Start a goroutine to track the instance status
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		// Set a timeout of 10 minutes
		timeout := time.After(10 * time.Minute)
		startTime := time.Now()

		for {
			select {
			case <-timeout:
				log.Printf("Timeout reached for instance %s after %v. Current state: %s",
					instance.ID, time.Since(startTime), instance.LifecycleState)
				return
			case <-ticker.C:
				// Get instance status
				instance, err := h.ociClient.GetInstance(instance.ID)
				if err != nil {
					log.Printf("Error getting instance status: %v", err)
					continue
				}

				// Log instance details
				log.Printf("Instance %s status: %s", instance.DisplayName, instance.LifecycleState)

				// Check for terminal states
				switch instance.LifecycleState {
				case "RUNNING":
					log.Printf("Baremetal instance %s is now running with private IP %s",
						instance.DisplayName, instance.PrivateIP)
					return
				case "TERMINATED", "TERMINATING":
					log.Printf("Baremetal instance %s was terminated", instance.DisplayName)
					return
				case "STOPPED", "STOPPING":
					log.Printf("Baremetal instance %s was stopped", instance.DisplayName)
					return
				case "FAULTED":
					log.Printf("Baremetal instance %s encountered a fault", instance.DisplayName)
					return
				}
			}
		}
	}()

	// Return the instance ID immediately
	response := ProvisionResponse{
		Message:    "Provisioning initiated",
		InstanceID: instance.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
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
