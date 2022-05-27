// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.

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
	"io/ioutil"
	"strings"

	"k8s.io/apimachinery/pkg/util/json"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/libcalico-go/lib/options"

	docopt "github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	libipam "github.com/projectcalico/calico/libcalico-go/lib/ipam"
)

// IPAM takes keyword with an IP address then calls the subcommands.
func Release(args []string, version string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> ipam release [--ip=<IP>] [--from-report=<REPORT>]... [--config=<CONFIG>] [--force] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
     --ip=<IP>                 IP address to release.
     --from-report=<REPORT>    Release all leaked addresses from the report.  If multiple reports are specified then
                               only leaked IPs common to all reports will be released - by generating reports at 
                               different times, e.g. separated by an hour, this can be used to provide additional 
                               certainty that the IPs are truly leaked rather than in a transient state of assignment.
                               At least one of the reports should be newly generated.
     --force                   Force release of leaked addresses.
  -c --config=<CONFIG>         Path to the file containing connection configuration in
                               YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The ipam release command releases an IP address from the Calico IP Address
  Manager that was been previously assigned to an endpoint.  When an IP address
  is released, it becomes available for assignment to any endpoint.

  Note that this does not remove the IP from any existing endpoints that may be
  using it, so only use this command to clean up addresses from endpoints that
  were not cleanly removed from Calico.
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

	ctx := context.Background()

	// Load config.
	cf := parsedArgs["--config"].(string)
	cfg, err := clientmgr.LoadClientConfig(cf)
	if err != nil {
		return err
	}

	// Set QPS - we want to increase this because we may need to send many IPAM requests
	// in a short period of time in order to release a large number of addresses.
	cfg.Spec.K8sClientQPS = float32(100)

	// Create a new backend client.
	client, err := clientmgr.NewClientFromConfig(cfg)
	if err != nil {
		return err
	}

	ipamClient := client.IPAM()

	if report := parsedArgs["--from-report"]; report != nil {
		reportFiles := parsedArgs["--from-report"].([]string)
		if len(reportFiles) > 0 {
			force := false
			if parsedArgs["--force"] != nil {
				force = parsedArgs["--force"].(bool)
			}
			err = releaseFromReports(ctx, client, force, reportFiles, version)
			if err != nil {
				return err
			}
			fmt.Println("You may now unlock the data store.")
			return nil
		}
	}

	if ip := parsedArgs["--ip"]; ip != nil {
		passedIP := parsedArgs["--ip"].(string)
		ip := argutils.ValidateIP(passedIP)
		opt := libipam.ReleaseOptions{Address: ip.IP.String()}

		// Call ReleaseIPs releases the IP and returns an empty slice as unallocatedIPs if
		// release was successful else it returns back the slice with the IP passed in.
		unallocatedIPs, err := ipamClient.ReleaseIPs(ctx, opt)
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
	}

	return nil
}

func releaseFromReports(ctx context.Context, c client.Interface, force bool, reportFiles []string, version string) error {
	// Grab the cluster info for checking against the report metadata.
	clusterInfo, err := c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		return err
	}

	// Load the reports.
	var foundCurrent bool
	var reports []Report
	for _, reportFile := range reportFiles {
		r := Report{}
		bytes, err := ioutil.ReadFile(reportFile)
		if err != nil {
			return err
		}
		err = json.Unmarshal(bytes, &r)
		if err != nil {
			return err
		}

		// Make sure the metadata from the report matches the cluster.
		if clusterInfo.Spec.ClusterGUID != r.ClusterGUID {
			// This check cannot be overridden using the --force option, because it is critical.
			return fmt.Errorf("Cluster does not match the provided report (%s): mismatched cluster GUID. Refusing to release.", reportFile)
		}
		if version != r.Version {
			if !force {
				return fmt.Errorf("The provided report (%s) was produced using a different version (%s) of calicoctl. Refusing to release.", reportFile, r.Version)
			} else {
				fmt.Println("WARNING: Report was produced using a different version of calicoctl. Ignoring due to --force option")
			}
		}

		// At least one of the reports should have the current cluster info resource version.
		if clusterInfo.ResourceVersion == r.ClusterInfoRevision {
			foundCurrent = true
		}

		reports = append(reports, r)
	}

	// At least one of the reports should match the current cluster info revision.
	if !foundCurrent {
		return fmt.Errorf("The provided reports are all stale - at least one should be up-to-date. Please generate a new report while the data store is locked and try again.")
	}

	// Datastore should be locked unless forcing.
	if clusterInfo.Spec.DatastoreReady == nil || *clusterInfo.Spec.DatastoreReady {
		if !force {
			return fmt.Errorf("Data store is not locked. Either lock the data store, or re-run with --force.")
		} else {
			fmt.Println("WARNING: Data store is not locked. Ignoring due to --force option")
		}
	}

	// Take the intersection of the reports, we only want to release the "leaked" values that show in all the reports.
	var notInUseIPs map[string]libipam.ReleaseOptions
	var notInUseHandles set.Set
	for _, report := range reports {
		mergedIPs := make(map[string]libipam.ReleaseOptions)
		for _, allocations := range report.Allocations {
			for _, a := range allocations {
				if a.InUse {
					continue
				}
				if _, ok := notInUseIPs[a.IP]; notInUseIPs != nil && !ok {
					continue
				}
				mergedIPs[a.IP] = libipam.ReleaseOptions{
					Handle:         a.Handle,
					Address:        a.IP,
					SequenceNumber: a.SequenceNumber,
				}
			}
		}
		notInUseIPs = mergedIPs

		mergedHandles := set.New()
		for _, h := range report.LeakedHandles {
			if notInUseHandles == nil || notInUseHandles.Contains(h) {
				mergedHandles.Add(h)
			}
		}
		notInUseHandles = mergedHandles
	}

	ipsToRelease := []libipam.ReleaseOptions{}
	for _, opts := range notInUseIPs {
		ipsToRelease = append(ipsToRelease, opts)
	}
	if len(ipsToRelease) == 0 {
		fmt.Println("No addresses need to be released.")
		return nil
	}
	fmt.Printf("Releasing %d old IPs\n", len(ipsToRelease))

	unallocated, err := c.IPAM().ReleaseIPs(ctx, ipsToRelease...)
	if err != nil {
		return err
	}
	if len(unallocated) != 0 {
		fmt.Println("Warning: report contained addresses which are no longer allocated")
	} else {
		fmt.Printf("Released %d IPs successfully\n", len(ipsToRelease))
	}

	fmt.Printf("Deleting %d handles...\n", notInUseHandles.Len())
	fmt.Println("Key: '.' = Deleted OK; 'x' = already gone.")
	// Get the backend client.
	type accessor interface {
		Backend() bapi.Client
	}
	bc := c.(accessor).Backend()
	notInUseHandles.Iter(func(item interface{}) error {
		handleID := item.(string)
		handleKey := model.IPAMHandleKey{HandleID: handleID}
		_, err := bc.Delete(ctx, handleKey, "")
		if err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
				fmt.Print("x")
			} else {
				fmt.Printf("\nDeleting handle %s failed: %s.\n", err.Error())
			}
		} else {
			fmt.Print(".")
		}
		return nil
	})

	return nil
}
