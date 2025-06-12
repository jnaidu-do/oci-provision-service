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
	"strconv"
	"sync"

	"github.com/jayanthnaidu/oci-provision-service/pkg/oci"
	"golang.org/x/crypto/ssh"
)

// Handler represents the HTTP handlers for the API
type Handler struct {
	ociClient *oci.Client
}

// NewHandler creates a new handler instance
func NewHandler(ociClient *oci.Client) (*Handler, error) {
	log.Printf("Creating new handler instance")
	return &Handler{
		ociClient: ociClient,
	}, nil
}

// ProvisionRequest represents the new request format
type ProvisionRequest struct {
	CloudProvider  string `json:"cloudProvider"`
	Operation      string `json:"operation"`
	Region         string `json:"region"`
	NumHypervisors string `json:"num_hypervisors"`
	RegionID       int    `json:"regionId"`
	Token          string `json:"token"`
}

// InstanceInfo represents information about a provisioned instance
type InstanceInfo struct {
	ID        string `json:"id"`
	PrivateIP string `json:"private_ip"`
}

// ProvisionResponse represents the response format
type ProvisionResponse struct {
	Message   string         `json:"message"`
	Instances []InstanceInfo `json:"instances"`
}

// ProvisionedInstanceDetails represents the details of a provisioned instance
type ProvisionedInstanceDetails struct {
	InstanceID     string `json:"instance_id"`
	PrivateIP      string `json:"private_ip"`
	LifecycleState string `json:"lifecycle_state"`
	DisplayName    string `json:"display_name"`
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

// ProvisionBareMetal handles the POST /api/v1/provision-baremetal endpoint
func (h *Handler) ProvisionBareMetal(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Set("Access-Control-Allow-Origin", "http://10.36.24.61:80/")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// Handle preflight requests
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Printf("Received provision request from %s", r.RemoteAddr)

	var req ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if req.CloudProvider != "oracle" {
		http.Error(w, "Only oracle cloud provider is supported", http.StatusBadRequest)
		return
	}

	numHypervisors, err := strconv.Atoi(req.NumHypervisors)
	if err != nil {
		http.Error(w, "Invalid number of hypervisors", http.StatusBadRequest)
		return
	}

	if numHypervisors <= 0 {
		http.Error(w, "Number of hypervisors must be greater than 0", http.StatusBadRequest)
		return
	}

	if numHypervisors >= 3 {
		http.Error(w, "Number of hypervisors must be lesser than 3", http.StatusBadRequest)
		return
	}

	// Create a slice to store instance information
	instances := make([]InstanceInfo, 0, numHypervisors)
	errorChan := make(chan error, numHypervisors)
	var wg sync.WaitGroup

	// Launch instances concurrently
	for i := 0; i < numHypervisors; i++ {
		wg.Add(1)
		go func(instanceNum int) {
			defer wg.Done()

			// Generate a unique display name for each instance
			randomSuffix, err := generateRandomSuffix()
			if err != nil {
				log.Printf("Error generating random suffix: %v", err)
				errorChan <- err
				return
			}
			displayName := fmt.Sprintf("baremetal-instance-%d-%s", instanceNum+1, randomSuffix)
			log.Printf("Generated display name: %s", displayName)

			// Launch the instance
			instance, err := h.ociClient.LaunchBareMetalInstance(oci.InstanceConfig{
				CompartmentID:      os.Getenv("OCI_COMPARTMENT_ID"),
				AvailabilityDomain: os.Getenv("OCI_AVAILABILITY_DOMAIN"),
				ImageID:            os.Getenv("OCI_IMAGE_ID"),
				SubnetID:           os.Getenv("OCI_SUBNET_ID"),
				PEMPrivateKey:      os.Getenv("OCI_PEM_PRIVATE_KEY"),
				DisplayName:        displayName,
				CloudInitScript:    os.Getenv("CLOUD_INIT_SCRIPT"),
			})
			if err != nil {
				log.Printf("Error launching instance %s: %v", displayName, err)
				errorChan <- err
				return
			}

			// Add instance info to the slice
			instances = append(instances, InstanceInfo{
				ID:        instance.ID,
				PrivateIP: instance.PrivateIP,
			})
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

	// Return the instance information immediately
	response := ProvisionResponse{
		Message:   fmt.Sprintf("Provisioning initiated for %d instance(s)", numHypervisors),
		Instances: instances,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
}

// TrackBareMetal handles the GET /api/v1/track-baremetal endpoint
func (h *Handler) TrackBareMetal(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
	w.Header().Set("Access-Control-Allow-Origin", "http://10.36.24.61:80/")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// Handle preflight requests
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

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
