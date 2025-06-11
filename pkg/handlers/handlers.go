package handlers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"

	"github.com/jayanthnaidu/oci-provision-service/pkg/oci"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
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

// ProvisionBareMetalRequest represents the request body for provisioning a bare metal instance
type ProvisionBareMetalRequest struct {
	CompartmentID       string `json:"compartment_id"`
	AvailabilityDomain  string `json:"availability_domain"`
	ImageID             string `json:"image_id"`
	SubnetID            string `json:"subnet_id"`
	PEMPrivateKey       string `json:"pem_private_key"`
	DisplayName         string `json:"display_name"`
	BootVolumeSizeInGBs *int   `json:"boot_volume_size_in_gbs,omitempty"`
}

// ProvisionBareMetalResponse represents the response for provisioning a bare metal instance
type ProvisionBareMetalResponse struct {
	Status         string `json:"status"`
	InstanceID     string `json:"instance_id"`
	LifecycleState string `json:"lifecycle_state"`
}

// TrackBareMetalResponse represents the response for tracking a bare metal instance
type TrackBareMetalResponse struct {
	InstanceID     string `json:"instance_id"`
	LifecycleState string `json:"lifecycle_state"`
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

// ProvisionBareMetal handles the POST /api/v1/provision_baremetal endpoint
func (h *Handler) ProvisionBareMetal(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request to provision bare metal instance from %s", r.RemoteAddr)

	var req ProvisionBareMetalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding request body: %v", err)
		sendError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	log.Printf("Request details - Compartment: %s, AD: %s, Image: %s, Subnet: %s, DisplayName: %s",
		req.CompartmentID, req.AvailabilityDomain, req.ImageID, req.SubnetID, req.DisplayName)

	// Validate required fields
	if req.CompartmentID == "" || req.AvailabilityDomain == "" || req.ImageID == "" ||
		req.SubnetID == "" || req.PEMPrivateKey == "" || req.DisplayName == "" {
		log.Printf("Missing required fields in request")
		sendError(w, http.StatusBadRequest, "Missing required fields")
		return
	}

	// Convert PEM key to SSH public key
	log.Printf("Converting PEM key to SSH public key")
	sshPublicKey, err := convertPEMToSSHPublicKey(req.PEMPrivateKey)
	if err != nil {
		log.Printf("Error converting PEM key: %v", err)
		sendError(w, http.StatusBadRequest, fmt.Sprintf("Invalid PEM key: %v", err))
		return
	}
	log.Printf("Successfully converted PEM key to SSH public key")

	// Create launch instance request
	log.Printf("Creating launch instance request")
	launchReq := core.LaunchInstanceRequest{
		LaunchInstanceDetails: core.LaunchInstanceDetails{
			CompartmentId:      common.String(req.CompartmentID),
			AvailabilityDomain: common.String(req.AvailabilityDomain),
			ImageId:            common.String(req.ImageID),
			SubnetId:           common.String(req.SubnetID),
			DisplayName:        common.String(req.DisplayName),
			Shape:              common.String(oci.BareMetalShape),
			Metadata: map[string]string{
				"ssh_authorized_keys": sshPublicKey,
			},
		},
	}

	// Launch the instance
	log.Printf("Initiating instance launch")
	instance, err := h.ociClient.LaunchBareMetalInstance(r.Context(), &launchReq)
	if err != nil {
		log.Printf("Error launching instance: %v", err)
		sendError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to launch instance: %v", err))
		return
	}
	log.Printf("Successfully initiated instance launch. Instance ID: %s, State: %s", *instance.Id, instance.LifecycleState)

	// Send success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(ProvisionBareMetalResponse{
		Status:         "Bare metal instance provisioning initiated",
		InstanceID:     *instance.Id,
		LifecycleState: string(instance.LifecycleState),
	})
	log.Printf("Sent success response for instance %s", *instance.Id)
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

	instance, err := h.ociClient.GetInstance(r.Context(), instanceID)
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
	json.NewEncoder(w).Encode(TrackBareMetalResponse{
		InstanceID:     *instance.Id,
		LifecycleState: string(instance.LifecycleState),
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
