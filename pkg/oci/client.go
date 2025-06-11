package oci

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const (
	BareMetalShape = "BM.Optimized3.36"
)

// Client represents an OCI client with necessary service clients
type Client struct {
	computeClient core.ComputeClient
}

// NewClient creates a new OCI client using instance principals or local configuration
func NewClient() (*Client, error) {
	log.Printf("Initializing OCI client")
	var provider common.ConfigurationProvider
	var err error

	// Check if we're running locally (development mode)
	if os.Getenv("OCI_LOCAL_DEV") == "true" {
		log.Printf("Using local configuration (OCI_LOCAL_DEV=true)")
		// Use local configuration from environment variables
		provider = common.DefaultConfigProvider()
	} else {
		log.Printf("Using instance principals authentication")
		// Use instance principals
		provider, err = auth.InstancePrincipalConfigurationProvider()
		if err != nil {
			log.Printf("Failed to create instance principal provider: %v", err)
			return nil, fmt.Errorf("failed to create instance principal provider: %v", err)
		}
	}

	log.Printf("Creating compute client")
	computeClient, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		log.Printf("Failed to create compute client: %v", err)
		return nil, fmt.Errorf("failed to create compute client: %v", err)
	}

	log.Printf("OCI client initialized successfully")
	return &Client{
		computeClient: computeClient,
	}, nil
}

// LaunchBareMetalInstance launches a new bare metal instance
func (c *Client) LaunchBareMetalInstance(ctx context.Context, req *core.LaunchInstanceRequest) (*core.Instance, error) {
	log.Printf("Launching bare metal instance with shape: %s", BareMetalShape)
	// Ensure the shape is set to bare metal
	req.Shape = common.String(BareMetalShape)

	log.Printf("Sending launch instance request to OCI")
	response, err := c.computeClient.LaunchInstance(ctx, *req)
	if err != nil {
		log.Printf("Failed to launch instance: %v", err)
		return nil, fmt.Errorf("failed to launch instance: %v", err)
	}

	log.Printf("Instance launched successfully with ID: %s", *response.Instance.Id)
	return &response.Instance, nil
}

// GetInstance retrieves the current state of an instance
func (c *Client) GetInstance(ctx context.Context, instanceID string) (*core.Instance, error) {
	log.Printf("Getting instance details for ID: %s", instanceID)
	req := core.GetInstanceRequest{
		InstanceId: common.String(instanceID),
	}

	log.Printf("Sending get instance request to OCI")
	response, err := c.computeClient.GetInstance(ctx, req)
	if err != nil {
		log.Printf("Failed to get instance %s: %v", instanceID, err)
		return nil, fmt.Errorf("failed to get instance: %v", err)
	}

	log.Printf("Retrieved instance %s with state: %s", instanceID, response.Instance.LifecycleState)
	return &response.Instance, nil
}
