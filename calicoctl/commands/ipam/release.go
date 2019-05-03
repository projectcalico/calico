// Copyright (c) 2016 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipam

import (
	"context"
	"fmt"
	"strings"

	"github.com/projectcalico/libcalico-go/lib/net"

	docopt "github.com/docopt/docopt-go"
	"github.com/projectcalico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calicoctl/calicoctl/commands/constants"
)

// IPAM takes keyword with an IP address then calls the subcommands.
func Release(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl ipam release --ip=<IP> [--config=<CONFIG>]

Options:
  -h --help             Show this screen.
     --ip=<IP>          IP address to release.
  -c --config=<CONFIG>  Path to the file containing connection configuration in
                        YAML or JSON format.
                        [default: ` + constants.DefaultConfigPath + `]

Description:
  The ipam release command releases an IP address from the Calico IP Address
  Manager that was been previously assigned to an endpoint.  When an IP address
  is released, it becomes available for assignment to any endpoint.

  Note that this does not remove the IP from any existing endpoints that may be
  using it, so only use this command to clean up addresses from endpoints that
  were not cleanly removed from Calico.
`
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	ctx := context.Background()

	// Create a new backend client from env vars.
	cf := parsedArgs["--config"].(string)
	client, err := clientmgr.NewClient(cf)
	if err != nil {
		return err
	}

	ipamClient := client.IPAM()
	passedIP := parsedArgs["--ip"].(string)

	ip := argutils.ValidateIP(passedIP)
	ips := []net.IP{ip}

	// Call ReleaseIPs releases the IP and returns an empty slice as unallocatedIPs if
	// release was successful else it returns back the slice with the IP passed in.
	unallocatedIPs, err := ipamClient.ReleaseIPs(ctx, ips)
	if err != nil {
		return fmt.Errorf("Error: %v", err)
	}

	// Couldn't release the IP if the slice is not empty or IP might already be released/unassigned.
	// This is not exactly an error, so not returning it to the caller.
	if len(unallocatedIPs) != 0 {
		return fmt.Errorf("IP address %s is not assigned", ip)
	}

	// If unallocatedIPs slice is empty then IP was released Successfully.
	fmt.Printf("Successfully released IP address %s\n", ip)

	return nil
}
