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
	"sync"
	"time"

	"github.com/jayanthnaidu/oci-provision-service/pkg/kafka"
	"github.com/jayanthnaidu/oci-provision-service/pkg/oci"
	"golang.org/x/crypto/ssh"
)

// Handler represents the HTTP handlers for the API
type Handler struct {
	ociClient *oci.Client
	producer  *kafka.Producer
}

// NewHandler creates a new handler instance
func NewHandler(ociClient *oci.Client) (*Handler, error) {
	log.Printf("Creating new handler instance")

	// Initialize Kafka producer
	log.Printf("Initializing Kafka producer")
	brokerAddr := os.Getenv("KAFKA_BROKER_ADDR")
	if brokerAddr == "" {
		log.Printf("Warning: KAFKA_BROKER_ADDR not set, Kafka functionality will be disabled")
		return &Handler{
			ociClient: ociClient,
		}, nil
	}

	topic := os.Getenv("KAFKA_TOPIC")
	if topic == "" {
		topic = "filteredEvents" // default topic
	}

	// Create a channel for the producer result
	producerChan := make(chan *kafka.Producer, 1)
	errChan := make(chan error, 1)

	// Start Kafka producer initialization in a goroutine
	go func() {
		log.Printf("Creating Kafka producer with broker: %s and topic: %s", brokerAddr, topic)
		producer, err := kafka.NewProducer(brokerAddr, topic)
		if err != nil {
			errChan <- err
			return
		}
		producerChan <- producer
	}()

	// Wait for either the producer or an error with a timeout
	select {
	case producer := <-producerChan:
		log.Printf("Kafka producer initialized successfully")
		return &Handler{
			ociClient: ociClient,
			producer:  producer,
		}, nil
	case err := <-errChan:
		log.Printf("Warning: Failed to initialize Kafka producer: %v. Continuing without Kafka...", err)
		return &Handler{
			ociClient: ociClient,
		}, nil
	case <-time.After(10 * time.Second):
		log.Printf("Warning: Timeout while initializing Kafka producer. Continuing without Kafka...")
		return &Handler{
			ociClient: ociClient,
		}, nil
	}
}

// ProvisionRequest represents the new request format
type ProvisionRequest struct {
	CloudProvider  string `json:"cloudProvider"`
	Operation      string `json:"operation"`
	Region         string `json:"region"`
	NumHypervisors int    `json:"num_hypervisors"`
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
	if req.CloudProvider != "oracle" {
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

	// Create a slice to store instance information
	instances := make([]InstanceInfo, 0, req.NumHypervisors)
	errorChan := make(chan error, req.NumHypervisors)
	var wg sync.WaitGroup

	// Launch instances concurrently
	for i := 0; i < req.NumHypervisors; i++ {
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

			// Start a goroutine to track the instance status
			go func(inst *oci.Instance) {
				ticker := time.NewTicker(30 * time.Second)
				defer ticker.Stop()

				// Set a timeout of 10 minutes
				timeout := time.After(10 * time.Minute)
				startTime := time.Now()

				for {
					select {
					case <-timeout:
						log.Printf("Timeout reached for instance %s after %v. Current state: %s",
							inst.ID, time.Since(startTime), inst.LifecycleState)
						return
					case <-ticker.C:
						// Get instance status
						instance, err := h.ociClient.GetInstance(inst.ID)
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

							// Send Kafka message
							if h.producer != nil {
								msg := kafka.EventMessage{
									InstanceID:  instance.ID,
									PrivateIP:   instance.PrivateIP,
									DisplayName: instance.DisplayName,
									Token:       req.Token,
									Timestamp:   time.Now(),
								}

								if err := h.producer.SendEvent(msg); err != nil {
									log.Printf("Error sending Kafka message for instance %s: %v",
										instance.DisplayName, err)
								} else {
									log.Printf("Sent Kafka message for instance %s", instance.DisplayName)
								}
							} else {
								log.Printf("Kafka producer not available, skipping message for instance %s", instance.DisplayName)
							}
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
			}(instance)
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
		Message:   fmt.Sprintf("Provisioning initiated for %d instance(s)", req.NumHypervisors),
		Instances: instances,
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
