package calicoclient

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// How long to wait between attempts to reach an unreachable datastore.
const datastoreRetryInterval = 1 * time.Second

// CreateClient loads the client config from environments and creates the
// Calico client.
func CreateClient() (*apiconfig.CalicoAPIConfig, client.Interface) {
	// Load the client config from environment.
	cfg, err := apiconfig.LoadClientConfig("")
	if err != nil {
		fmt.Printf("ERROR: Error loading datastore config: %s\n", err)
		os.Exit(1)
	}

	// An explicit value of true is required to wait for the datastore, matching
	// the check the startup sequence makes before probing the connection.
	waitForDatastore := os.Getenv("WAIT_FOR_DATASTORE") == "true"

	c, err := createClient(cfg, waitForDatastore, client.New, time.Sleep)
	if err != nil {
		fmt.Printf("ERROR: Error accessing the Calico datastore: %s\n", err)
		os.Exit(1)
	}

	return cfg, c
}

// createClient builds the client, retrying while the datastore is unreachable if
// the caller asked to wait for it.
//
// The etcdv3 backend validates the connection when the client is built, so an
// unreachable datastore fails here rather than on the first read. Without the
// retry, WAIT_FOR_DATASTORE would be bypassed: we would exit before the startup
// sequence ever got as far as waiting.
func createClient(
	cfg *apiconfig.CalicoAPIConfig,
	waitForDatastore bool,
	newClient func(apiconfig.CalicoAPIConfig) (client.Interface, error),
	sleep func(time.Duration),
) (client.Interface, error) {
	for {
		c, err := newClient(*cfg)
		if err == nil {
			return c, nil
		}

		// Only an unreachable datastore is worth waiting for; anything else
		// (bad config, bad credentials) will not fix itself.
		var datastoreErr cerrors.ErrorDatastoreError
		if !waitForDatastore || !errors.As(err, &datastoreErr) {
			return nil, err
		}

		fmt.Printf("Waiting for the Calico datastore: %s\n", err)
		sleep(datastoreRetryInterval)
	}
}
