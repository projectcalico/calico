// Copyright (c) 2015-2021 Tigera, Inc. All rights reserved.
//
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

package ipamplugin

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	cniSpecVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/gofrs/flock"
	"github.com/prometheus/common/log"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/seedrng"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/cni-plugin/pkg/upgrade"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func Main(version string) {
	// Make sure the RNG is seeded.
	seedrng.EnsureSeeded()

	// Set up logging formatting.
	logrus.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file/line no information.
	logrus.AddHook(&logutils.ContextHook{})

	// Display the version on "-v", otherwise just delegate to the skel code.
	// Use a new flag set so as not to conflict with existing libraries which use "flag"
	flagSet := flag.NewFlagSet("calico-ipam", flag.ExitOnError)

	versionFlag := flagSet.Bool("v", false, "Display version")
	upgradeFlag := flagSet.Bool("upgrade", false, "Upgrade from host-local")
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if *versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}

	// Migration logic
	if *upgradeFlag {
		logrus.Info("migrating from host-local to calico-ipam...")
		ctxt := context.Background()

		// nodename associates IPs to this node.
		nodename := os.Getenv("KUBERNETES_NODE_NAME")
		if nodename == "" {
			logrus.Fatal("KUBERNETES_NODE_NAME not specified, refusing to migrate...")
		}
		logCtxt := logrus.WithField("node", nodename)

		// calicoClient makes IPAM calls.
		cfg, err := apiconfig.LoadClientConfig("")
		if err != nil {
			logCtxt.Fatal("failed to load api client config")
		}
		cfg.Spec.DatastoreType = apiconfig.Kubernetes
		calicoClient, err := client.New(*cfg)
		if err != nil {
			logCtxt.Fatal("failed to initialize api client")
		}

		// Perform the migration.
		for {
			err := upgrade.Migrate(ctxt, calicoClient, nodename)
			if err == nil {
				break
			}
			logCtxt.WithError(err).Error("failed to migrate ipam, retrying...")
			time.Sleep(time.Second)
		}
		logCtxt.Info("migration from host-local to calico-ipam complete")
		os.Exit(0)
	}

	skel.PluginMain(cmdAdd, nil, cmdDel,
		cniSpecVersion.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "1.0.0"),
		"Calico CNI IPAM "+version)
}

type ipamArgs struct {
	cnitypes.CommonArgs
	IP net.IP `json:"ip,omitempty"`
}

func cmdAdd(args *skel.CmdArgs) error {
	conf := types.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	nodename := utils.DetermineNodename(conf)

	utils.ConfigureLogging(conf)

	calicoClient, err := utils.CreateClient(conf)
	if err != nil {
		return err
	}

	epIDs, err := utils.GetIdentifiers(args, nodename)
	if err != nil {
		return err
	}

	epIDs.WEPName, err = epIDs.CalculateWorkloadEndpointName(false)
	if err != nil {
		return fmt.Errorf("error constructing WorkloadEndpoint name: %s", err)
	}

	handleID := utils.GetHandleID(conf.Name, args.ContainerID, epIDs.WEPName)

	logger := logrus.WithFields(logrus.Fields{
		"Workload":    epIDs.WEPName,
		"ContainerID": epIDs.ContainerID,
		"HandleID":    handleID,
	})

	ipamArgs := ipamArgs{}
	if err = cnitypes.LoadArgs(args.Args, &ipamArgs); err != nil {
		return err
	}

	// We attach important attributes to the allocation.
	attrs := map[string]string{
		ipam.AttributeNode:      nodename,
		ipam.AttributeTimestamp: time.Now().UTC().String(),
	}
	if epIDs.Pod != "" {
		attrs[ipam.AttributePod] = epIDs.Pod
		attrs[ipam.AttributeNamespace] = epIDs.Namespace
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	r := &cniv1.Result{}
	if ipamArgs.IP != nil {
		logger.Infof("Calico CNI IPAM request IP: %v", ipamArgs.IP)

		assignArgs := ipam.AssignIPArgs{
			IP:       cnet.IP{IP: ipamArgs.IP},
			HandleID: &handleID,
			Hostname: nodename,
			Attrs:    attrs,
		}
		logger.WithField("assignArgs", assignArgs).Info("Assigning provided IP")
		assignIPWithLock := func() error {
			unlock := acquireIPAMLockBestEffort(conf.IPAMLockFile)
			defer unlock()
			return calicoClient.IPAM().AssignIP(ctx, assignArgs)
		}
		err := assignIPWithLock()
		if err != nil {
			return err
		}

		var ipNetwork net.IPNet

		if ipamArgs.IP.To4() == nil {
			// It's an IPv6 address.
			ipNetwork = net.IPNet{IP: ipamArgs.IP, Mask: net.CIDRMask(128, 128)}
			r.IPs = append(r.IPs, &cniv1.IPConfig{
				Address: ipNetwork,
			})

			logger.WithField("result.IPs", ipamArgs.IP).Info("Appending an IPv6 address to the result")
		} else {
			// It's an IPv4 address.
			ipNetwork = net.IPNet{IP: ipamArgs.IP, Mask: net.CIDRMask(32, 32)}
			r.IPs = append(r.IPs, &cniv1.IPConfig{
				Address: ipNetwork,
			})

			logger.WithField("result.IPs", ipamArgs.IP).Info("Appending an IPv4 address to the result")
		}
	} else {
		// Default to assigning an IPv4 address
		num4 := 1
		if conf.IPAM.AssignIpv4 != nil && *conf.IPAM.AssignIpv4 == "false" {
			num4 = 0
		}

		// Default to NOT assigning an IPv6 address
		num6 := 0
		if conf.IPAM.AssignIpv6 != nil && *conf.IPAM.AssignIpv6 == "true" {
			num6 = 1
		}

		logger.Infof("Calico CNI IPAM request count IPv4=%d IPv6=%d", num4, num6)

		v4pools, err := utils.ResolvePools(ctx, calicoClient, conf.IPAM.IPv4Pools, true)
		if err != nil {
			return err
		}

		v6pools, err := utils.ResolvePools(ctx, calicoClient, conf.IPAM.IPv6Pools, false)
		if err != nil {
			return err
		}

		logger.Debugf("Calico CNI IPAM handle=%s", handleID)
		var maxBlocks int
		if conf.WindowsUseSingleNetwork {
			// When running in single-network mode (for kube-proxy compatibility), limit the
			// number of blocks we're allowed to create.
			logrus.Info("Running in single-HNS-network mode, limiting number of IPAM blocks to 1.")
			maxBlocks = 1
		}
		assignArgs := ipam.AutoAssignArgs{
			Num4:             num4,
			Num6:             num6,
			HandleID:         &handleID,
			Hostname:         nodename,
			IPv4Pools:        v4pools,
			IPv6Pools:        v6pools,
			MaxBlocksPerHost: maxBlocks,
			Attrs:            attrs,
			IntendedUse:      v3.IPPoolAllowedUseWorkload,
		}
		if runtime.GOOS == "windows" {
			rsvdAttrWindows := &ipam.HostReservedAttr{
				StartOfBlock: 3,
				EndOfBlock:   1,
				Handle:       ipam.WindowsReservedHandle,
				Note:         "windows host rsvd",
			}
			assignArgs.HostReservedAttrIPv4s = rsvdAttrWindows
		}
		logger.WithField("assignArgs", assignArgs).Info("Auto assigning IP")
		autoAssignWithLock := func(calicoClient client.Interface, ctx context.Context, assignArgs ipam.AutoAssignArgs) (*ipam.IPAMAssignments, *ipam.IPAMAssignments, error) {
			// Acquire a best-effort host-wide lock to prevent multiple copies of the CNI plugin trying to assign
			// concurrently. AutoAssign is concurrency safe already but serialising the CNI plugins means that
			// we only attempt one IPAM claim at a time on the host's active IPAM block.  This reduces the load
			// on the API server by a factor of the number of concurrent requests.
			unlock := acquireIPAMLockBestEffort(conf.IPAMLockFile)
			defer unlock()
			return calicoClient.IPAM().AutoAssign(ctx, assignArgs)
		}
		v4Assignments, v6Assignments, err := autoAssignWithLock(calicoClient, ctx, assignArgs)
		var v4ips, v6ips []cnet.IPNet
		if v4Assignments != nil {
			v4ips = v4Assignments.IPs
		}
		if v6Assignments != nil {
			v6ips = v6Assignments.IPs
		}
		logger.Infof("Calico CNI IPAM assigned addresses IPv4=%v IPv6=%v", v4ips, v6ips)
		if err != nil {
			return err
		}

		// Check if IPv4 address assignment fails but IPv6 address assignment succeeds. Release IPs for the successful IPv6 address assignment.
		if num4 == 1 && v4Assignments != nil && len(v4Assignments.IPs) < num4 {
			if num6 == 1 && v6Assignments != nil && len(v6Assignments.IPs) > 0 {
				logger.Infof("Assigned IPv6 addresses but failed to assign IPv4 addresses. Releasing %d IPv6 addresses", len(v6Assignments.IPs))
				// Free the assigned IPv6 addresses when v4 address assignment fails.
				v6IPs := []ipam.ReleaseOptions{}
				for _, v6 := range v6Assignments.IPs {
					v6IPs = append(v6IPs, ipam.ReleaseOptions{Address: v6.IP.String()})
				}
				_, err := calicoClient.IPAM().ReleaseIPs(ctx, v6IPs...)
				if err != nil {
					log.Errorf("Error releasing IPv6 addresses %+v on IPv4 address assignment failure: %s", v6IPs, err)
				}
			}
		}

		// Check if IPv6 address assignment fails but IPv4 address assignment succeeds. Release IPs for the successful IPv4 address assignment.
		if num6 == 1 && v6Assignments != nil && len(v6Assignments.IPs) < num6 {
			if num4 == 1 && v4Assignments != nil && len(v4Assignments.IPs) > 0 {
				logger.Infof("Assigned IPv4 addresses but failed to assign IPv6 addresses. Releasing %d IPv4 addresses", len(v4Assignments.IPs))
				// Free the assigned IPv4 addresses when v4 address assignment fails.
				v4IPs := []ipam.ReleaseOptions{}
				for _, v4 := range v4Assignments.IPs {
					v4IPs = append(v4IPs, ipam.ReleaseOptions{Address: v4.IP.String()})
				}
				_, err := calicoClient.IPAM().ReleaseIPs(ctx, v4IPs...)
				if err != nil {
					log.Errorf("Error releasing IPv4 addresses %+v on IPv6 address assignment failure: %s", v4IPs, err)
				}
			}
		}

		if num4 == 1 {
			if err := v4Assignments.PartialFulfillmentError(); err != nil {
				return fmt.Errorf("failed to request IPv4 addresses: %w", err)
			}
			ipV4Network := net.IPNet{IP: v4Assignments.IPs[0].IP, Mask: v4Assignments.IPs[0].Mask}
			r.IPs = append(r.IPs, &cniv1.IPConfig{
				Address: ipV4Network,
			})
		}

		if num6 == 1 {
			if err := v6Assignments.PartialFulfillmentError(); err != nil {
				return fmt.Errorf("failed to request IPv6 addresses: %w", err)
			}
			ipV6Network := net.IPNet{IP: v6Assignments.IPs[0].IP, Mask: v6Assignments.IPs[0].Mask}
			r.IPs = append(r.IPs, &cniv1.IPConfig{
				Address: ipV6Network,
			})
		}

		logger.WithFields(logrus.Fields{"result.IPs": r.IPs}).Debug("IPAM Result")
	}

	// Print result to stdout, in the format defined by the requested cniVersion.
	return cnitypes.PrintResult(r, conf.CNIVersion)
}

type unlockFn func()

// acquireIPAMLockBestEffort attempts to acquire the IPAM file lock, blocking if needed.  If an error occurs
// (for example permissions or missing directory) then it returns immediately.  Returns a function that unlocks the
// lock again (or a no-op function if acquiring the lock failed).
func acquireIPAMLockBestEffort(path string) unlockFn {
	log.Info("About to acquire host-wide IPAM lock.")
	if path == "" {
		path = ipamLockPath
	}
	err := os.MkdirAll(filepath.Dir(path), 0777)
	if err != nil {
		logrus.WithError(err).Error("Failed to make directory for IPAM lock")
		// Fall through, still a slight chance the file is there for us to access.
	}
	ipamLock := flock.New(path)
	err = ipamLock.Lock()
	if err != nil {
		logrus.WithError(err).Error("Failed to grab IPAM lock, may contend for datastore updates")
		return func() {}
	}
	log.Info("Acquired host-wide IPAM lock.")
	return func() {
		err := ipamLock.Unlock()
		if err != nil {
			logrus.WithError(err).Warn("Failed to release IPAM lock; ignoring because process is about to exit.")
		} else {
			log.Info("Released host-wide IPAM lock.")
		}
	}
}

func cmdDel(args *skel.CmdArgs) error {
	conf := types.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	utils.ConfigureLogging(conf)

	calicoClient, err := utils.CreateClient(conf)
	if err != nil {
		return err
	}

	nodename := utils.DetermineNodename(conf)

	// Release the IP address by using the handle - which is workloadID.
	epIDs, err := utils.GetIdentifiers(args, nodename)
	if err != nil {
		return err
	}

	epIDs.WEPName, err = epIDs.CalculateWorkloadEndpointName(false)
	if err != nil {
		return fmt.Errorf("error constructing WorkloadEndpoint name: %s", err)
	}

	handleID := utils.GetHandleID(conf.Name, args.ContainerID, epIDs.WEPName)
	logger := logrus.WithFields(logrus.Fields{
		"Workload":    epIDs.WEPName,
		"ContainerID": epIDs.ContainerID,
		"HandleID":    handleID,
	})

	logger.Info("Releasing address using handleID")
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	// Acquire a best-effort host-wide lock to prevent multiple copies of the CNI plugin trying to assign/delete
	// concurrently. ReleaseXXX is concurrency safe already but serialising the CNI plugins means that
	// we only attempt one IPAM update at a time.  This reduces the load on the API server by a factor of the
	// number of concurrent requests with essentially no downside.
	unlock := acquireIPAMLockBestEffort(conf.IPAMLockFile)
	defer unlock()

	if err := calicoClient.IPAM().ReleaseByHandle(ctx, handleID); err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			logger.WithError(err).Error("Failed to release address")
			return err
		}
		logger.Warn("Asked to release address but it doesn't exist. Ignoring")
	} else {
		logger.Info("Released address using handleID")
	}

	// Calculate the workloadID to account for v2.x upgrades.
	workloadID := epIDs.ContainerID
	if epIDs.Orchestrator == "k8s" {
		workloadID = fmt.Sprintf("%s.%s", epIDs.Namespace, epIDs.Pod)
	}

	logger.Info("Releasing address using workloadID")
	if err := calicoClient.IPAM().ReleaseByHandle(ctx, workloadID); err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			logger.WithError(err).Error("Failed to release address")
			return err
		}
		logger.WithField("workloadID", workloadID).Debug("Asked to release address but it doesn't exist. Ignoring")
	} else {
		logger.WithField("workloadID", workloadID).Info("Released address using workloadID")
	}

	return nil
}
