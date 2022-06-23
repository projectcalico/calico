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
  <BINARY_NAME> ipam split <CIDR> <NUMBER> [--config=<CONFIG>] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection configuration in
                               YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The ipam split command splits an IP pool specified by the specified CIDR into
  the specified number of smaller IP pools. Each child IP pool will be of equal
  size. IP pools can only be split into a number of smaller pools that is a power
  of 2.

Examples:
  # Split the IP pool specified by 172.0.0.0/8 into 2 smaller pools
  calicoctl ipam split 172.0.0.0/8 2
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

	// TODO: Check that the node kube-controller is not running.
	// Check env variable ENABLED_CONTROLLERS
	// Check the KubeControllersConfiguration

	// Find the specified IP pool.
	poolList, err := client.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		return fmt.Errorf("Unable to list IP pools to find the pool specified by %s", parsedArgs["<CIDR>"])
	}

	var oldPool *apiv3.IPPool
	for _, pool := range poolList.Items {
		if pool.Spec.CIDR == parsedArgs["<CIDR>"] {
			oldPool = &pool
		}
	}

	if oldPool == nil {
		return fmt.Errorf("Unable to find IP pool covering the specified CIDR %s", parsedArgs["<CIDR>"])
	}

	// Disable the specified IP pool.
	oldPool.Spec.Disabled = true
	oldPool, err = client.IPPools().Update(ctx, oldPool, options.SetOptions{})
	if err != nil {
		return fmt.Errorf("Error disabling IP pool %s", parsedArgs["<CIDR>"])
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
	for i, cidr := range splitCIDRs {
		splitPool := &apiv3.IPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("split-%s-%d", oldPool.GetObjectMeta().GetName(), i+1),
			},
			Spec: apiv3.IPPoolSpec{
				CIDR: cidr,
				//Block size and encapsulation are preserved.
				BlockSize: oldPool.Spec.BlockSize,
				VXLANMode: oldPool.Spec.VXLANMode,
				IPIPMode:  oldPool.Spec.IPIPMode,
			},
		}

		splitPool, err = client.IPPools().UnsafeCreate(ctx, splitPool, options.SetOptions{})
		if err != nil {
			return fmt.Errorf("Error using unsafe create to make split pool with cidr %s: %v", cidr, err)
		}
	}

	// Delete the old IP pool.
	_, err = client.IPPools().Delete(ctx, oldPool.GetObjectMeta().GetName(), options.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("Error removing the IP pool that was split %s: %v", oldPool.GetObjectMeta().GetName(), err)
	}

	// Output follow-up directions.
	fmt.Printf("IP Pool %s was successfully split into %d smaller pools. Please refer to the documentation for final steps.", oldPool.GetObjectMeta().GetName(), splitNum)

	return nil
}

func splitCIDR(oldCIDR string, parts int) ([]string, error) {
	// Validate that we are trying to split the CIDR into a valid number of child CIDRs.
	power := math.Log2(float64(parts))
	if math.IsNaN(power) || power == 0 {
		return []string{}, fmt.Errorf("Number to split CIDR into is not a valid power of 2: %s", parts)
	}

	// Convert the string version of the CIDR into a CIDR object.
	_, cidr, err := cnet.ParseCIDR(oldCIDR)
	if err != nil {
		return []string{}, fmt.Errorf("Error reading CIDR %s before attempting to split it", oldCIDR)
	}

	ones, bits := cidr.Mask.Size()
	if int(power)+ones > bits {
		return []string{}, fmt.Errorf("The CIDR %s is not large enough to be split into %s parts", oldCIDR, parts)
	}

	// Find the block size to increment over.
	blockSize := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bits-ones-int(power))), nil)

	// Mask the IP in case the CIDR isn't formatted nicely.
	mask := net.CIDRMask(ones, bits)
	maskedIP := cnet.IP{cidr.IP.Mask(mask)}

	// Create the child CIDRs
	splitCIDRs := make([]string, parts)
	i := 0
	for i < parts {
		splitCIDR := cnet.IPNet{
			net.IPNet{
				IP:   maskedIP.IP,
				Mask: net.CIDRMask(ones+int(power), bits),
			},
		}

		splitCIDRs[i] = splitCIDR.String()
		maskedIP = cnet.IncrementIP(maskedIP, blockSize)
		i += 1
	}

	return splitCIDRs, nil
}
