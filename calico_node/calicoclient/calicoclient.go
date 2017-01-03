package calicoclient

import (
	"fmt"
	"os"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
)

// CreateClient loads the client config from environments and creates the
// Calico client.
func CreateClient() (*api.CalicoAPIConfig, *client.Client) {
	// Load the client config from environment.
	cfg, err := client.LoadClientConfig("")
	if err != nil {
		fmt.Printf("ERROR: Error loading datastore config: %s", err)
		os.Exit(1)
	}
	c, err := client.New(*cfg)
	if err != nil {
		fmt.Printf("ERROR: Error accessing the Calico datastore: %s", err)
		os.Exit(1)
	}

	return cfg, c
}
