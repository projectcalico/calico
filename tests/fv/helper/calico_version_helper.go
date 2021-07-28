package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/docopt/docopt-go"
	clientv3 "github.com/projectcalico/libcalico-go/lib/clientv3"

	"github.com/projectcalico/calicoctl/v3/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calicoctl/v3/calicoctl/commands/constants"
)

var VERSION string

func main() {
	doc := `Usage:
  calico_version_helper [options]

Options:
  -h --help                 Show this screen.
  -v --version=<version>    Version to set.
                            [default: ` + VERSION + `]
  -c --config=<config>      Path to the file containing connection
                            configuration in YAML or JSON format.
                            [default: ` + constants.DefaultConfigPath + `]
  --context=<context>       The name of the kubeconfig context to use.

Description:
  Set CalicoVersion in ClusterInformation.
`
	parsedArgs, err := docopt.ParseDoc(doc)
	if err != nil {
		fmt.Printf("Could not parse arguments: %s, err: %v\n", strings.Join(os.Args[1:], " "), err)
		os.Exit(1)
	}

	if context := parsedArgs["--context"]; context != nil {
		os.Setenv("K8S_CURRENT_CONTEXT", context.(string))
	}

	cf, _ := parsedArgs["--config"].(string)

	cfg, err := clientmgr.LoadClientConfig(cf)
	if err != nil {
		fmt.Printf("Could not load client config: %v\n", err)
		os.Exit(1)
	}

	// Get the backend client for updating cluster info and migrating IPAM.
	client, err := clientv3.New(*cfg)
	if err != nil {
		fmt.Printf("Could not create client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	calicoVersion, _ := parsedArgs["--version"].(string)

	if err := client.EnsureInitialized(ctx, calicoVersion, ""); err != nil {
		fmt.Printf("Could not set calico version to %s: %v\n", calicoVersion, err)
		os.Exit(1)
	}

	fmt.Printf("Calico version set to %s\n", calicoVersion)
}
