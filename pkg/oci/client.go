package oci

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"golang.org/x/crypto/ssh"
)

const (
	BareMetalShape = "BM.Standard.A1.160"
)

// InstanceConfig holds the configuration for launching an instance
type InstanceConfig struct {
	CompartmentID      string
	AvailabilityDomain string
	ImageID            string
	SubnetID           string
	PEMPrivateKey      string
	DisplayName        string
}

// Instance represents a simplified view of an OCI instance
type Instance struct {
	ID             string
	PrivateIP      string
	LifecycleState string
	DisplayName    string
}

// Client represents an OCI client
type Client struct {
	computeClient core.ComputeClient
	vcnClient     core.VirtualNetworkClient
}

// NewClient creates a new OCI client
func NewClient() (*Client, error) {
	log.Printf("Initializing OCI client")

	// Check if we're in local development mode
	if os.Getenv("OCI_LOCAL_DEV") == "true" {
		log.Printf("Using local development configuration")
		configProvider := common.DefaultConfigProvider()
		computeClient, err := core.NewComputeClientWithConfigurationProvider(configProvider)
		if err != nil {
			return nil, fmt.Errorf("failed to create compute client: %v", err)
		}

		vcnClient, err := core.NewVirtualNetworkClientWithConfigurationProvider(configProvider)
		if err != nil {
			return nil, fmt.Errorf("failed to create VCN client: %v", err)
		}

		return &Client{
			computeClient: computeClient,
			vcnClient:     vcnClient,
		}, nil
	}

	// Production configuration
	configProvider := common.DefaultConfigProvider()
	computeClient, err := core.NewComputeClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute client: %v", err)
	}

	vcnClient, err := core.NewVirtualNetworkClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create VCN client: %v", err)
	}

	return &Client{
		computeClient: computeClient,
		vcnClient:     vcnClient,
	}, nil
}

// LaunchBareMetalInstance launches a bare metal instance
func (c *Client) LaunchBareMetalInstance(config InstanceConfig) (*Instance, error) {
	log.Printf("Launching bare metal instance with display name: %s", config.DisplayName)

	// Convert PEM key to SSH public key
	sshPublicKey, err := convertPEMToSSHPublicKey(config.PEMPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PEM key: %v", err)
	}

	// Create launch instance request
	launchReq := core.LaunchInstanceRequest{
		LaunchInstanceDetails: core.LaunchInstanceDetails{
			CompartmentId:      common.String(config.CompartmentID),
			AvailabilityDomain: common.String(config.AvailabilityDomain),
			ImageId:            common.String(config.ImageID),
			SubnetId:           common.String(config.SubnetID),
			DisplayName:        common.String(config.DisplayName),
			Shape:              common.String(BareMetalShape),
			Metadata: map[string]string{
				"ssh_authorized_keys": sshPublicKey,
			},
		},
	}

	// Launch the instance
	ctx := context.Background()
	response, err := c.computeClient.LaunchInstance(ctx, launchReq)
	if err != nil {
		return nil, fmt.Errorf("failed to launch instance: %v", err)
	}

	// Get the VNIC attachment to get the private IP
	vnicAttachments, err := c.computeClient.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{
		CompartmentId: common.String(config.CompartmentID),
		InstanceId:    response.Instance.Id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get VNIC attachments: %v", err)
	}

	if len(vnicAttachments.Items) == 0 {
		return nil, fmt.Errorf("no VNIC attachments found for instance")
	}

	// Get the VNIC details
	vnic, err := c.vcnClient.GetVnic(ctx, core.GetVnicRequest{
		VnicId: vnicAttachments.Items[0].VnicId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get VNIC details: %v", err)
	}

	// Convert to our Instance type
	instance := &Instance{
		ID:             *response.Instance.Id,
		PrivateIP:      *vnic.Vnic.PrivateIp,
		LifecycleState: string(response.Instance.LifecycleState),
		DisplayName:    *response.Instance.DisplayName,
	}

	log.Printf("Successfully launched instance %s", instance.ID)
	return instance, nil
}

// GetInstance gets an instance by ID
func (c *Client) GetInstance(instanceID string) (*Instance, error) {
	log.Printf("Getting instance %s", instanceID)

	ctx := context.Background()
	request := core.GetInstanceRequest{
		InstanceId: common.String(instanceID),
	}

	response, err := c.computeClient.GetInstance(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to get instance: %v", err)
	}

	// Get the VNIC attachment to get the private IP
	vnicAttachments, err := c.computeClient.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{
		CompartmentId: response.Instance.CompartmentId,
		InstanceId:    response.Instance.Id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get VNIC attachments: %v", err)
	}

	if len(vnicAttachments.Items) == 0 {
		return nil, fmt.Errorf("no VNIC attachments found for instance")
	}

	// Get the VNIC details
	vnic, err := c.vcnClient.GetVnic(ctx, core.GetVnicRequest{
		VnicId: vnicAttachments.Items[0].VnicId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get VNIC details: %v", err)
	}

	// Convert to our Instance type
	instance := &Instance{
		ID:             *response.Instance.Id,
		PrivateIP:      *vnic.Vnic.PrivateIp,
		LifecycleState: string(response.Instance.LifecycleState),
		DisplayName:    *response.Instance.DisplayName,
	}

	log.Printf("Successfully retrieved instance %s with state: %s", instance.ID, instance.LifecycleState)
	return instance, nil
}

// convertPEMToSSHPublicKey converts a PEM private key to an SSH public key
func convertPEMToSSHPublicKey(pemKey string) (string, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to create public key: %v", err)
	}

	return string(ssh.MarshalAuthorizedKey(publicKey)), nil
}
