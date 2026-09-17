package calicoclient

import (
	"fmt"
	"os"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// CreateClient loads the client config from environments and creates the
// Calico client. The component names the caller to the API server, which records
// it as the field manager on every write the client makes.
func CreateClient(component string) (*apiconfig.CalicoAPIConfig, client.Interface) {
	// Load the client config from environment.
	cfg, err := apiconfig.LoadClientConfig("")
	if err != nil {
		fmt.Printf("ERROR: Error loading datastore config: %s\n", err)
		os.Exit(1)
	}
	cfg.Spec.UserAgent = apiconfig.UserAgentFor(component)
	c, err := client.New(*cfg)
	if err != nil {
		fmt.Printf("ERROR: Error accessing the Calico datastore: %s\n", err)
		os.Exit(1)
	}

	return cfg, c
}
