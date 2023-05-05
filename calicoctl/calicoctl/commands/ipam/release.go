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
	"os"
	"runtime"
	"strings"
	"time"

	docopt "github.com/docopt/docopt-go"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	libipam "github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// Release implements the "calicoctl ipam release" command, which supports releasing single IPs and releasing
// batches of leaked IPs and handles from an IPAM report.
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
		bytes, err := os.ReadFile(reportFile)
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
	notInUseIPs, notInUseHandles := mergeReports(reports)

	// Release any leaked IPs.
	if len(notInUseIPs) > 0 {
		releaseIPs(ctx, c, notInUseIPs)
	} else {
		fmt.Println("Report didn't contain any leaked IPs to clean up.")
	}

	// Release any leaked handles.
	if len(notInUseHandles) > 0 {
		releaseHandles(notInUseHandles, c)
	} else {
		fmt.Println("Report didn't contain any handles to clean up.")
	}

	return nil
}

func releaseIPs(ctx context.Context, c clientv3.Interface, notInUseIPs map[string]libipam.ReleaseOptions) {
	var ipsToRelease []libipam.ReleaseOptions
	for _, opts := range notInUseIPs {
		ipsToRelease = append(ipsToRelease, opts)
	}
	fmt.Printf("Releasing %d old IPs...\n", len(ipsToRelease))

	unallocated, err := c.IPAM().ReleaseIPs(ctx, ipsToRelease...)
	if err != nil {
		fmt.Printf("An error occured while releasing some IPs: %s.  "+
			"Problems are often caused by an out-of-date IPAM report.  "+
			"Try regenerating the IPAM report and retry.\n", err)
	} else {
		fmt.Printf("Released %d IPs successfully\n", len(ipsToRelease)-len(unallocated))
	}
	if len(unallocated) != 0 {
		fmt.Printf("%d addresses marked as leaked in the report had already been cleaned up.\n", len(unallocated))
	}
}

func mergeReports(reports []Report) (notInUseIPs map[string]libipam.ReleaseOptions, notInUseHandles map[string]HandleInfo) {
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

		mergedHandles := map[string]HandleInfo{}
		for _, h := range report.LeakedHandles {
			if notInUseHandles == nil {
				// First pass, collect everything.
				mergedHandles[h.ID] = h
			} else if oldH, ok := notInUseHandles[h.ID]; ok && oldH.Revision == h.Revision {
				// Subsequent pass, only collect things that haven't changed between reports.
				mergedHandles[h.ID] = h
			}
		}
		notInUseHandles = mergedHandles
	}
	return notInUseIPs, notInUseHandles
}

func releaseHandles(notInUseHandles map[string]HandleInfo, c clientv3.Interface) {
	fmt.Printf("Deleting %d handles...\n", len(notInUseHandles))
	fmt.Println("Key: '.' = Deleted OK; 'x' = skip, handle missing/changed.")
	// Get the backend client.
	type accessor interface {
		Backend() bapi.Client
	}
	var numReleased, numConflict, numErrors int
	bc := c.(accessor).Backend()

	type result struct {
		Handle HandleInfo
		Err    error
	}
	handlesC := make(chan HandleInfo)
	resultsC := make(chan result)
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			for handleInfo := range handlesC {
				err := deleteHandle(bc, handleInfo)
				resultsC <- result{
					Handle: handleInfo,
					Err:    err,
				}
			}
		}()
	}

	go func() {
		for _, handleInfo := range notInUseHandles {
			handlesC <- handleInfo
		}
		close(handlesC)
	}()

	for i := 0; i < len(notInUseHandles); i++ {
		result := <-resultsC
		err := result.Err
		if err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
				numConflict++
				fmt.Print("x")
			} else if _, ok := err.(errors.ErrorResourceUpdateConflict); ok {
				numConflict++
				fmt.Print("x")
			} else {
				numErrors++
				fmt.Printf("\nDeleting handle %s failed: %s.\n", result.Handle.ID, err.Error())
			}
		} else {
			numReleased++
			fmt.Print(".")
		}
	}
	fmt.Println()
	fmt.Printf("Released %d handles; %d skipped; %d errors.\n",
		numReleased, numConflict, numErrors)
}

func deleteHandle(bc bapi.Client, handleInfo HandleInfo) error {
	handleKey := model.IPAMHandleKey{HandleID: handleInfo.ID}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Note: getting the latest cached revision here and then checking it locally so that we can't get a
	// "revision compacted" error.  It should be safe to read from the cache since the handles we're deleting
	// should have been stale for a long time.
	kvp, err := bc.Get(ctx, handleKey, "0")
	if err != nil {
		return err
	}
	if kvp.Revision != handleInfo.Revision || !uidsEqual(handleInfo.UID, kvp.UID) {
		return errors.ErrorResourceUpdateConflict{
			Err:        fmt.Errorf("IPAM handle revision or UID didn't match"),
			Identifier: handleKey,
		}
	}

	// Must use DeleteKVP for IPAM handles (not Delete) since KDD requires the UID information from the KVP struct.
	_, err = bc.DeleteKVP(ctx, kvp)

	return err
}

func uidsEqual(a, b *types.UID) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
