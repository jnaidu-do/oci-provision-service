package oci

import (
	"context"
	"fmt"
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
	var provider common.ConfigurationProvider
	var err error

	// Check if we're running locally (development mode)
	if os.Getenv("OCI_LOCAL_DEV") == "true" {
		// Use local configuration from environment variables
		provider = common.DefaultConfigProvider()
	} else {
		// Use instance principals
		provider, err = auth.InstancePrincipalConfigurationProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create instance principal provider: %v", err)
		}
	}

	computeClient, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute client: %v", err)
	}

	return &Client{
		computeClient: computeClient,
	}, nil
}

// LaunchBareMetalInstance launches a new bare metal instance
func (c *Client) LaunchBareMetalInstance(ctx context.Context, req *core.LaunchInstanceRequest) (*core.Instance, error) {
	// Ensure the shape is set to bare metal
	req.Shape = common.String(BareMetalShape)

	response, err := c.computeClient.LaunchInstance(ctx, *req)
	if err != nil {
		return nil, fmt.Errorf("failed to launch instance: %v", err)
	}

	return &response.Instance, nil
}

// GetInstance retrieves the current state of an instance
func (c *Client) GetInstance(ctx context.Context, instanceID string) (*core.Instance, error) {
	req := core.GetInstanceRequest{
		InstanceId: common.String(instanceID),
	}

	response, err := c.computeClient.GetInstance(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get instance: %v", err)
	}

	return &response.Instance, nil
}
