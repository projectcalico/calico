// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	"math"
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/docopt/docopt-go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func Split(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> ipam split <NUMBER> [--cidr=<CIDR>] [--name=<POOL_NAME>] [--config=<CONFIG>] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection configuration in
                               YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --cidr=<CIDR>             CIDR of the IP pool to split.
     --name=<POOL_NAME>        Name of the IP pool to split.
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The ipam split command splits an IP pool specified by the specified CIDR or name
  into the specified number of smaller IP pools. Each child IP pool will be of equal
  size. IP pools can only be split into a number of smaller pools that is a power
  of 2.

Examples:
  # Split the IP pool specified by 172.0.0.0/8 into 2 smaller pools
  <BINARY_NAME> ipam split --cidr=172.0.0.0/8 2
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	err = common.CheckVersionMismatch(parsedArgs["--config"], parsedArgs["--allow-version-mismatch"])
	if err != nil {
		return err
	}

	// Validate that a name or CIDR is provided to search for the IP pool.
	var oldPoolCIDR, oldPoolName string
	if cidr := parsedArgs["--cidr"]; cidr != nil {
		oldPoolCIDR = parsedArgs["--cidr"].(string)
	}
	if name := parsedArgs["--name"]; name != nil {
		oldPoolName = parsedArgs["--name"].(string)
	}
	if oldPoolCIDR == "" && oldPoolName == "" {
		return fmt.Errorf("No name or CIDR provided. Provide a name or CIDR to denote the IP pool to split.")
	}

	cf := parsedArgs["--config"].(string)
	// Get the backend client.
	client, err := clientmgr.NewClient(cf)
	if err != nil {
		return err
	}

	// Check that the datastore is locked
	ctx := context.Background()
	locked, err := common.CheckLocked(ctx, client)
	if err != nil {
		return fmt.Errorf("Error while checking if datastore was locked: %s", err)
	} else if !locked {
		return fmt.Errorf("Datastore is not locked. Run the `calicoctl datastore migrate lock` command in order split the IP pools.")
	}

	// Find the IP pool to split
	var oldPool *apiv3.IPPool
	if oldPoolName != "" {
		oldPool, err = client.IPPools().Get(ctx, oldPoolName, options.GetOptions{})
		if err != nil {
			return fmt.Errorf("Unable to find IP pool with name %s: %v", oldPoolName, err)
		}
	} else if oldPoolCIDR != "" {
		poolList, err := client.IPPools().List(ctx, options.ListOptions{})
		if err != nil {
			return fmt.Errorf("Unable to list IP pools to find the pool specified by %s", oldPoolCIDR)
		}

		for _, pool := range poolList.Items {
			if pool.Spec.CIDR == oldPoolCIDR {
				oldPool = &pool
			}
		}
	}

	if oldPool == nil {
		return fmt.Errorf("Unable to find IP pool %s covering the specified CIDR %s", oldPoolName, oldPoolCIDR)
	}

	// Disable the specified IP pool.
	oldPool.Spec.Disabled = true
	oldPool, err = client.IPPools().Update(ctx, oldPool, options.SetOptions{})
	if err != nil {
		return fmt.Errorf("Error disabling IP pool %s", oldPoolCIDR)
	}

	// Calculate the split pool CIDRs.
	numString := parsedArgs["<NUMBER>"].(string)
	splitNum, err := strconv.Atoi(numString)
	if err != nil {
		return fmt.Errorf("Error reading number to split IP pools into. %s is not a valid number: %v", numString, err)
	}

	splitCIDRs, err := splitCIDR(oldPool.Spec.CIDR, splitNum)
	if err != nil {
		return fmt.Errorf("Error splitting the CIDR %s into %d CIDRs: %v", oldPool.Spec.CIDR, splitNum, err)
	}

	// Create the new split pools using UnsafeCreate.
	poolsCreated := make([]*apiv3.IPPool, splitNum)
	for i, cidr := range splitCIDRs {
		poolCopy := oldPool.DeepCopyObject()
		splitPool, ok := poolCopy.(*apiv3.IPPool)
		if !ok {
			return fmt.Errorf("Error copying metadata out from old IP pool: %s", oldPool.GetObjectMeta().GetName())
		}

		// Clear out unneeded metadata
		splitPool.GetObjectMeta().SetUID("")
		splitPool.GetObjectMeta().SetResourceVersion("")
		splitPool.GetObjectMeta().SetGeneration(0)
		splitPool.GetObjectMeta().SetSelfLink("")
		splitPool.GetObjectMeta().SetCreationTimestamp(metav1.Time{})

		// Set the new name
		newName := fmt.Sprintf("split-%s-%d", oldPool.GetObjectMeta().GetName(), i)
		// Max K8s resource name is 253 characters
		// TODO: Think of a better way of naming split pools.
		if len(newName) > 253 {
			// The split name adds 8 additional characters, modify the old pool name to fit with those additional 8 characters.
			newName = fmt.Sprintf("split-%s-%d", oldPool.GetObjectMeta().GetName()[:245], i)
		}
		splitPool.GetObjectMeta().SetName(newName)
		splitPool.GetObjectMeta().SetGenerateName("")

		// Set the new CIDR
		splitPool.Spec.CIDR = cidr

		// Enable the IP pool
		splitPool.Spec.Disabled = false

		_, err = client.IPPools().UnsafeCreate(ctx, splitPool, options.SetOptions{})
		if err != nil {
			return fmt.Errorf("Error using unsafe create to make split pool with cidr %s: %v", cidr, err)
		}

		poolsCreated[i] = splitPool
	}

	// Delete the old IP pool.
	// Use UnsafeDelete which will do everything Delete does except for removing the associated affinities.
	_, err = client.IPPools().UnsafeDelete(ctx, oldPool.GetObjectMeta().GetName(), options.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("Error removing the IP pool that was split %s: %v", oldPool.GetObjectMeta().GetName(), err)
	}

	// Output follow-up directions.
	fmt.Printf("IP Pool %s was successfully split into %d smaller pools.", oldPool.GetObjectMeta().GetName(), splitNum)
	for _, splitPool := range poolsCreated {
		fmt.Printf("Created %s with CIDR %s.\n", splitPool.GetObjectMeta().GetName(), splitPool.Spec.CIDR)
	}
	fmt.Print("Please refer to the documentation for final steps.")

	return nil
}

func splitCIDR(oldCIDR string, parts int) ([]string, error) {
	// Validate that we are trying to split the CIDR into a valid number of child CIDRs.
	power := math.Log2(float64(parts))
	if math.IsNaN(power) || power == 0 || math.Trunc(power) != power {
		return nil, fmt.Errorf("Number to split CIDR into is not a valid power of 2: %d", parts)
	}

	// Convert the string version of the CIDR into a CIDR object.
	_, cidr, err := cnet.ParseCIDR(oldCIDR)
	if err != nil {
		return nil, fmt.Errorf("Error reading CIDR %s before attempting to split it", oldCIDR)
	}

	ones, bits := cidr.Mask.Size()
	if int(power)+ones > bits {
		return nil, fmt.Errorf("The CIDR %s is not large enough to be split into %d parts", oldCIDR, parts)
	}

	// Find the block size to increment over.
	newPoolSize := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bits-ones-int(power))), nil)

	// Mask the IP in case the CIDR isn't formatted nicely.
	mask := net.CIDRMask(ones, bits)
	maskedIP := cnet.IP{IP: cidr.IP.Mask(mask)}

	// Create the child CIDRs
	splitCIDRs := make([]string, parts)
	for i := 0; i < parts; i++ {
		splitCIDR := cnet.IPNet{
			IPNet: net.IPNet{
				IP:   maskedIP.IP,
				Mask: net.CIDRMask(ones+int(power), bits),
			},
		}

		splitCIDRs[i] = splitCIDR.String()
		maskedIP = cnet.IncrementIP(maskedIP, newPoolSize)
	}

	return splitCIDRs, nil
}
