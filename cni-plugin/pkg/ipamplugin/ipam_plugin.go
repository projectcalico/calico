// Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
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
	"path"
	"path/filepath"
	"runtime"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	cniSpecVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/gofrs/flock"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/k8s"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/cni-plugin/pkg/upgrade"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func Main(version string) {
	// Set up logging formatting.
	logutils.ConfigureFormatter("ipam")

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

	funcs := skel.CNIFuncs{
		Add:   cmdAdd,
		Check: nil,
		Del:   cmdDel,
	}

	skel.PluginMainFuncs(funcs,
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

	// Check VM address persistence setting first (always, regardless of pod type).
	ipPersistenceEnabled := getKubeVirtVMAddressPersistence(calicoClient)

	// Always detect VMI info so we can reject migration targets when persistence is disabled.
	vmiInfo, err := getVMIInfoForPod(conf, epIDs)
	if err != nil {
		return fmt.Errorf("failed to get VMI info: %w", err)
	}

	// Reject migration target pods when persistence is disabled.
	if vmiInfo != nil && !ipPersistenceEnabled && vmiInfo.IsMigrationTarget() {
		logrus.Error("Live migration target pod rejected: KubeVirtVMAddressPersistence is disabled")
		return fmt.Errorf("live migration target pod is not allowed when KubeVirtVMAddressPersistence is disabled")
	}

	// Use VM-based handle ID only when both vmiInfo is present and persistence is enabled.
	var handleID string
	if vmiInfo != nil && ipPersistenceEnabled {
		// Use VMI-based handle ID for IP stability across VMI pod recreations/migrations
		// Handle ID is based on hash(namespace/vmiName) for persistence across VMI recreation
		handleID = createVMIHandleID(conf.Name, vmiInfo)
		logrus.WithFields(logrus.Fields{
			"pod":               epIDs.Pod,
			"namespace":         epIDs.Namespace,
			"vmiName":           vmiInfo.GetName(),
			"vmiUID":            vmiInfo.GetVMIUID(),
			"isMigrationTarget": vmiInfo.IsMigrationTarget(),
			"handleID":          handleID,
		}).Info("Detected KubeVirt virt-launcher pod, using VMI-based handle ID")
	} else {
		// Default handle ID based on container ID
		handleID = utils.GetHandleID(conf.Name, args.ContainerID, epIDs.WEPName)
	}

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
	// Add VMI attributes if this is a virt-launcher pod with persistence enabled
	if vmiInfo != nil && ipPersistenceEnabled {
		attrs[ipam.AttributeVMIName] = vmiInfo.GetName()
		attrs[ipam.AttributeVMIUID] = vmiInfo.GetVMIUID()
		if vmUID := vmiInfo.GetVMUID(); vmUID != "" {
			attrs[ipam.AttributeVMUID] = vmUID
		}

		isMigrationTarget := vmiInfo.IsMigrationTarget()
		if isMigrationTarget {
			attrs[ipam.AttributeVMIMUID] = vmiInfo.GetVMIMigrationUID()
		}

		// Check if IPs already exist for this VMI handle and reuse them.
		// - Source pod: reuses IPs from a previous pod with the same VMI (pod recreation).
		//   If no IPs exist, falls through to normal AutoAssign.
		// - Migration target: IPs must exist (allocated by the source pod).
		reuseExistingIPs, err := handleVirtLauncherPod(calicoClient, handleID, attrs, conf, logger, isMigrationTarget)
		if err != nil {
			return err
		}
		if reuseExistingIPs {
			return nil
		}
		// Source pod with no existing IPs - fall through to normal allocation
	}

	r := &cniv1.Result{}
	if ipamArgs.IP != nil {
		logger.Infof("Calico CNI IPAM request IP: %v", ipamArgs.IP)

		assignArgs := ipam.AssignIPArgs{
			IP:       cnet.IP{IP: ipamArgs.IP},
			HandleID: &handleID,
			Hostname: nodename,
			Attrs:    attrs,
		}

		// For VMI pods with persistence enabled, set MaxAllocPerIPVersion=1 to ensure only one IP per IP version per VMI.
		if vmiInfo != nil && ipPersistenceEnabled {
			assignArgs.MaxAllocPerIPVersion = 1
		}

		logger.WithField("assignArgs", assignArgs).Info("Assigning provided IP")
		assignIPWithLock := func() error {
			unlock := acquireIPAMLockBestEffort(conf.IPAMLockFile)
			defer unlock()

			// Only start the timeout after we get the lock. When there's a
			// thundering herd of new pods, acquiring the lock can take a while.
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()

			if err := maybeUpgradeIPAM(ctx, calicoClient.IPAM(), nodename); err != nil {
				return fmt.Errorf("failed to upgrade IPAM database: %w", err)
			}

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

		var v4pools, v6pools []cnet.IPNet
		{
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			v4pools, err = utils.ResolvePools(ctx, calicoClient, conf.IPAM.IPv4Pools, true)
			if err != nil {
				return err
			}
		}
		{
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			v6pools, err = utils.ResolvePools(ctx, calicoClient, conf.IPAM.IPv6Pools, false)
			if err != nil {
				return err
			}
		}

		logger.Debugf("Calico CNI IPAM handle=%s", handleID)
		var maxBlocks int
		if conf.WindowsUseSingleNetwork {
			// When running in single-network mode (for kube-proxy compatibility), limit the
			// number of blocks we're allowed to create.
			logrus.Info("Running in single-HNS-network mode, limiting number of IPAM blocks to 1.")
			maxBlocks = 1
		}
		// Get namespace information for namespaceSelector support
		namespace := epIDs.Namespace
		var namespaceObj *corev1.Namespace

		// Only attempt to fetch namespace if we have Kubernetes configuration and a valid namespace
		if (conf.Kubernetes.Kubeconfig != "" || conf.Policy.PolicyType == "k8s") && namespace != "" {
			logger.Debugf("Getting namespace for: %s", namespace)

			namespaceObj, err = getNamespace(conf, namespace, logger)
			if err != nil {
				logger.WithError(err).Errorf("Failed to get namespace for %s", namespace)
				return fmt.Errorf("failed to get namespace %s: %w", namespace, err)
			}
			logger.Debugf("Got namespace for %s: %v", namespace, namespaceObj.Labels)
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
			Namespace:        namespaceObj,
		}

		// For VMI pods with persistence enabled, set MaxAllocPerIPVersion=1 to ensure only one IP per IP version per VMI.
		// The IPAM library will automatically handle IP reuse if the handle already has an allocation.
		if vmiInfo != nil && ipPersistenceEnabled {
			assignArgs.MaxAllocPerIPVersion = 1
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
		autoAssignWithLock := func(calicoClient client.Interface, assignArgs ipam.AutoAssignArgs) (*ipam.IPAMAssignments, *ipam.IPAMAssignments, error) {
			// Acquire a best-effort host-wide lock to prevent multiple copies of the CNI plugin trying to assign
			// concurrently. AutoAssign is concurrency safe already but serialising the CNI plugins means that
			// we only attempt one IPAM claim at a time on the host's active IPAM block.  This reduces the load
			// on the API server by a factor of the number of concurrent requests.
			unlock := acquireIPAMLockBestEffort(conf.IPAMLockFile)
			defer unlock()

			// Only start the timeout after we get the lock. When there's a
			// thundering herd of new pods, acquiring the lock can take a while.
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()

			return calicoClient.IPAM().AutoAssign(ctx, assignArgs)
		}
		v4Assignments, v6Assignments, err := autoAssignWithLock(calicoClient, assignArgs)
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

				// Fresh timeout for cleanup.
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_, _, err := calicoClient.IPAM().ReleaseIPs(cleanupCtx, v6IPs...)
				if err != nil {
					logrus.Errorf("Error releasing IPv6 addresses %+v on IPv4 address assignment failure: %s", v6IPs, err)
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

				// Fresh timeout for cleanup.
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_, _, err := calicoClient.IPAM().ReleaseIPs(cleanupCtx, v4IPs...)
				if err != nil {
					logrus.Errorf("Error releasing IPv4 addresses %+v on IPv6 address assignment failure: %s", v4IPs, err)
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

	// Set routes in the result - one route per IP for normal pods
	// Note: For migration target pods, handleMigrationTarget() returns early with empty routes,
	// so we only reach here for normal pods
	for _, ipConfig := range r.IPs {
		r.Routes = append(r.Routes, &cnitypes.Route{
			Dst: ipConfig.Address,
		})
	}
	logger.WithField("routes", r.Routes).Debug("Added routes to result")

	// Print result to stdout, in the format defined by the requested cniVersion.
	return cnitypes.PrintResult(r, conf.CNIVersion)
}

const ipamUpgradedFilePath = "/var/run/calico/cni/ipam_upgraded"

func maybeUpgradeIPAM(ctx context.Context, ipamClient ipam.Interface, nodename string) error {
	if _, err := os.Stat(ipamUpgradedFilePath); err == nil {
		return nil
	}

	err := ipamClient.UpgradeHost(ctx, nodename)
	if err != nil {
		return fmt.Errorf("failed to upgrade IPAM database: %w", err)
	}

	if err := touchFile(ipamUpgradedFilePath); err != nil {
		return fmt.Errorf("failed to create IPAM upgrade marker file %s: %w", ipamUpgradedFilePath, err)
	}
	return nil
}

func touchFile(filePath string) error {
	dirPath, _ := path.Split(filePath)
	err := os.MkdirAll(dirPath, 0o755)
	if err != nil {
		return fmt.Errorf("failed to create directory for file %s: %w", filePath, err)
	}
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	err = file.Close()
	if err != nil {
		return fmt.Errorf("failure when closing file %s: %w", filePath, err)
	}
	return nil
}

type unlockFn func()

// acquireIPAMLockBestEffort attempts to acquire the IPAM file lock, blocking if needed.  If an error occurs
// (for example permissions or missing directory) then it returns immediately.  Returns a function that unlocks the
// lock again (or a no-op function if acquiring the lock failed).
func acquireIPAMLockBestEffort(path string) unlockFn {
	logrus.Info("About to acquire host-wide IPAM lock.")
	if path == "" {
		path = ipamLockPath
	}
	err := os.MkdirAll(filepath.Dir(path), 0o777)
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
	logrus.Info("Acquired host-wide IPAM lock.")
	return func() {
		err := ipamLock.Unlock()
		if err != nil {
			logrus.WithError(err).Warn("Failed to release IPAM lock; ignoring because process is about to exit.")
		} else {
			logrus.Info("Released host-wide IPAM lock.")
		}
	}
}

// createVMIHandleID creates a handle ID for a KubeVirt VMI pod based on namespace and VMI name.
// The handle ID format is: <networkName>.vmi.<namespace>.<vmiName> (length-limited to 128 chars)
// This ensures IP persistence across VMI pod recreations and live migrations since
// the VMI name and namespace remain stable (VM and VMI share the same name).
// This function delegates to ipam.CreateVMIHandleID to ensure consistent handle generation
// across CNI plugin and Felix.
func createVMIHandleID(confName string, vmiInfo *kubevirt.PodVMIInfo) string {
	return ipam.CreateVMIHandleID(confName, vmiInfo.GetNamespace(), vmiInfo.GetName())
}

// getVMIInfoForPod retrieves KubeVirt VirtualMachineInstance (VMI) information for a given pod.
// Returns (vmiInfo, nil) if the pod is a valid virt-launcher pod.
// Returns (nil, nil) if the pod is not a virt-launcher pod.
// Returns (nil, error) if there was an error retrieving or validating VMI information.
func getVMIInfoForPod(conf types.NetConf, epIDs *utils.WEPIdentifiers) (*kubevirt.PodVMIInfo, error) {
	// Only check for VMI info in Kubernetes orchestrator
	if epIDs.Orchestrator != "k8s" || epIDs.Pod == "" || epIDs.Namespace == "" {
		return nil, nil
	}

	// Create Kubernetes client
	k8sClient, err := k8s.NewK8sClient(conf, logrus.NewEntry(logrus.StandardLogger()))
	if err != nil {
		logrus.WithError(err).Error("Failed to create Kubernetes client for VMI detection")
		return nil, err
	}

	// Get the pod
	pod, err := k8sClient.CoreV1().Pods(epIDs.Namespace).Get(context.Background(), epIDs.Pod, metav1.GetOptions{})
	if err != nil {
		logrus.WithError(err).Error("Failed to get pod for VMI detection")
		return nil, err
	}

	// Create KubeVirt client for VMI verification
	virtClient, err := k8s.NewKubeVirtClient(conf, logrus.NewEntry(logrus.StandardLogger()))
	if err != nil {
		logrus.WithError(err).Error("Failed to create KubeVirt client for VMI detection")
		return nil, err
	}

	// Get and verify VMI info (queries VMI resource for verification)
	vmiInfo, err := kubevirt.GetPodVMIInfo(pod, virtClient)
	if err != nil {
		logrus.WithError(err).Error("Invalid virt-launcher pod configuration")
		return nil, err
	}

	return vmiInfo, nil
}

// getKubeVirtVMAddressPersistence retrieves the KubeVirtVMAddressPersistence setting from IPAMConfig.
// Returns true if VM address persistence is enabled (the default), false if explicitly disabled.
func getKubeVirtVMAddressPersistence(calicoClient client.Interface) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ipamConfig, err := calicoClient.IPAMConfiguration().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		logrus.WithError(err).Debug("Could not retrieve IPAMConfig, defaulting to VMAddressPersistenceEnabled")
		return true
	}

	if ipamConfig.Spec.KubeVirtVMAddressPersistence == nil {
		return true
	}

	return *ipamConfig.Spec.KubeVirtVMAddressPersistence != v3.VMAddressPersistenceDisabled
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

	// Check VM address persistence setting first (always, regardless of pod type).
	ipPersistenceEnabled := getKubeVirtVMAddressPersistence(calicoClient)

	// Always detect VMI info for logging, but only use VM-based handle when persistence is enabled.
	vmiInfo, err := getVMIInfoForPod(conf, epIDs)
	if err != nil {
		return fmt.Errorf("failed to get VMI info: %w", err)
	}

	// Use VM-based handle ID only when both vmiInfo is present and persistence is enabled.
	var handleID string
	if vmiInfo != nil && ipPersistenceEnabled {
		// Use VMI-based handle ID
		// Handle ID is based on hash(namespace/vmiName) for persistence across VMI recreation
		handleID = createVMIHandleID(conf.Name, vmiInfo)

		// VMI deletion status is already available from embedded VMIResource
		logrus.WithFields(logrus.Fields{
			"pod":                   epIDs.Pod,
			"namespace":             epIDs.Namespace,
			"vmiName":               vmiInfo.GetName(),
			"vmiUID":                vmiInfo.GetVMIUID(),
			"vmDeletionInProgress":  vmiInfo.IsVMObjectDeletionInProgress(),
			"vmiDeletionInProgress": vmiInfo.IsVMIObjectDeletionInProgress(),
			"hasVMOwner":            vmiInfo.VMOwner != nil,
			"handleID":              handleID,
		}).Info("Detected KubeVirt virt-launcher pod deletion")
	} else {
		// Default handle ID based on container ID
		handleID = utils.GetHandleID(conf.Name, args.ContainerID, epIDs.WEPName)
	}

	logger := logrus.WithFields(logrus.Fields{
		"Workload":    epIDs.WEPName,
		"ContainerID": epIDs.ContainerID,
		"HandleID":    handleID,
	})

	logger.Info("Releasing address using handleID")

	// Acquire a best-effort host-wide lock to prevent multiple copies of the CNI plugin trying to assign/delete
	// concurrently. ReleaseXXX is concurrency safe already but serialising the CNI plugins means that
	// we only attempt one IPAM update at a time.  This reduces the load on the API server by a factor of the
	// number of concurrent requests with essentially no downside.
	unlock := acquireIPAMLockBestEffort(conf.IPAMLockFile)
	defer unlock()

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	// For VMI pods with persistence enabled, handle deletion based on VM/VMI deletion status.
	// IP persistence is only maintained while the VM (or standalone VMI) is alive.
	// - If VMI is owned by a VM: release when VM has DeletionTimestamp
	// - If VMI is standalone (no VM owner): release when VMI has DeletionTimestamp
	if vmiInfo != nil && ipPersistenceEnabled {
		shouldRelease := false
		if vmiInfo.VMOwner != nil {
			// VMI is owned by a VM - check VM deletion status
			shouldRelease = vmiInfo.IsVMObjectDeletionInProgress()
		} else {
			// Standalone VMI (no VM owner) - check VMI deletion status
			shouldRelease = vmiInfo.IsVMIObjectDeletionInProgress()
		}
		logger.WithFields(logrus.Fields{
			"shouldRelease": shouldRelease,
			"hasVMOwner":    vmiInfo.VMOwner != nil,
		}).Info("Processing VMI pod deletion")

		// Get IPs allocated to this handle so we can clear their attributes
		ips, err := calicoClient.IPAM().IPsByHandle(ctx, handleID)
		if err != nil {
			logger.WithError(err).Warn("Failed to get IPs by handle")
			return err
		}

		// Build expected owner for verification
		expectedOwner := &ipam.AttributeOwner{
			Namespace: epIDs.Namespace,
			Name:      epIDs.Pod,
		}

		// First pass: Clear attributes that match this pod
		for _, ip := range ips {
			logger.WithField("ip", ip).Info("Attempting to clear pod attributes")

			// Get current AllocationAttribute
			attr, err := calicoClient.IPAM().GetAssignmentAttributes(ctx, ip)
			if err != nil {
				logger.WithError(err).WithField("ip", ip).Warn("Failed to get assignment attributes, skipping attribute cleanup")
				continue
			}

			// Check which attribute owner matches this pod using MatchAttributeOwner
			activeMatches := ipam.MatchAttributeOwner(attr.ActiveOwnerAttrs, expectedOwner)
			alternateMatches := ipam.MatchAttributeOwner(attr.AlternateOwnerAttrs, expectedOwner)

			// Prepare updates and preconditions based on which owner type matches
			var updates *ipam.OwnerAttributeUpdates
			var preconditions *ipam.OwnerAttributePreconditions
			var ownerType string

			if activeMatches {
				ownerType = "ActiveOwnerAttrs"
				updates = &ipam.OwnerAttributeUpdates{
					ClearActiveOwner: true,
				}
				preconditions = &ipam.OwnerAttributePreconditions{
					ExpectedActiveOwner: expectedOwner,
				}
			} else if alternateMatches {
				ownerType = "AlternateOwnerAttrs"
				updates = &ipam.OwnerAttributeUpdates{
					ClearAlternateOwner: true,
				}
				preconditions = &ipam.OwnerAttributePreconditions{
					ExpectedAlternateOwner: expectedOwner,
				}
			} else {
				logger.WithField("ip", ip).Debug("No matching attributes found for this pod, nothing to clear")
				continue
			}

			// Clear the matching owner attributes.
			// Note: There is a potential race condition between GetAssignmentAttributes and SetOwnerAttributes.
			// If Felix performs a SwapAttributes operation upon migration completion during this window,
			// the block attributes may have changed, causing SetOwnerAttributes to fail with a precondition
			// mismatch error. This is expected behavior - kubelet will retry the CNI DEL operation, and
			// on the subsequent attempt, GetAssignmentAttributes will read the updated attributes and
			// SetOwnerAttributes will succeed. This race condition should be extremely rare because it only
			// gets triggered when a migration target pod gets deleted around the same time migration is completing,
			// and the window is tiny (between GetAssignmentAttributes and SetOwnerAttributes).
			err = calicoClient.IPAM().SetOwnerAttributes(ctx, ip, handleID, updates, preconditions)
			if err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"ip":        ip,
					"ownerType": ownerType,
				}).Error("Failed to clear owner attributes")
				return err
			}
			logger.WithFields(logrus.Fields{
				"ip":        ip,
				"ownerType": ownerType,
			}).Info("Successfully cleared owner attributes")
		}

		// Second pass: Check if any owner attributes remain after clearing this pod's attributes
		anyOwnerAttributesRemain := false
		for _, ip := range ips {
			attr, err := calicoClient.IPAM().GetAssignmentAttributes(ctx, ip)
			if err != nil {
				logger.WithError(err).WithField("ip", ip).Error("Failed to get assignment attributes for post-cleanup check")
				return fmt.Errorf("failed to verify owner attributes after cleanup for IP %s: %w", ip, err)
			}

			// Check if any owner attributes exist
			if attr.ActiveOwnerAttrs != nil || attr.AlternateOwnerAttrs != nil {
				anyOwnerAttributesRemain = true
				logger.WithFields(logrus.Fields{
					"ip":                ip,
					"hasActiveOwner":    attr.ActiveOwnerAttrs != nil,
					"hasAlternateOwner": attr.AlternateOwnerAttrs != nil,
				}).Debug("Owner attributes still exist for this IP")
				break // No need to check remaining IPs
			}
		}

		// Only release the handle if the VM/VMI is being deleted AND all IPs have empty owner attributes
		if shouldRelease && !anyOwnerAttributesRemain {
			logger.Info("VM/VMI deletion in progress and all owner attributes empty - releasing IP by handle")
			if err := calicoClient.IPAM().ReleaseByHandle(ctx, handleID); err != nil {
				if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
					logger.WithError(err).Error("Failed to release address")
					return err
				}
				logger.Warn("Asked to release address but it doesn't exist. Ignoring")
			} else {
				logger.Info("Released address using handleID")
			}
		} else {
			logger.WithFields(logrus.Fields{
				"shouldRelease":            shouldRelease,
				"anyOwnerAttributesRemain": anyOwnerAttributesRemain,
			}).Info("Completed attribute cleanup - IP remains allocated to VMI")
		}

		return nil
	}

	// For non-VMI pods, use the standard release logic
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

// getNamespace retrieves namespace object using Kubernetes clientset
func getNamespace(conf types.NetConf, namespace string, logger *logrus.Entry) (*corev1.Namespace, error) {
	if namespace == "" {
		return nil, nil
	}

	// Create Kubernetes clientset
	k8sClient, err := k8s.NewK8sClient(conf, logger)
	if err != nil {
		return nil, err
	}

	// Get namespace directly from Kubernetes API
	ns, err := k8sClient.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return ns, nil
}

// handleMigrationTarget handles CNI ADD for a migration target pod.
// For migration targets, the IP(s) must already exist (allocated by source pod to VMI handle).
// This function retrieves the existing IP(s) and sets AlternateOwnerAttrs with target pod info.
// handleVirtLauncherPod handles IP allocation for KubeVirt virt-launcher pods by checking
// if IPs are already allocated to the VMI handle and reusing them.
//
// For source pods (isMigrationTarget=false):
//   - If existing IPs found: reuses them and sets ActiveOwnerAttrs. Returns (true, nil).
//   - If no existing IPs: returns (false, nil) so the caller proceeds with normal AutoAssign.
//
// For migration target pods (isMigrationTarget=true):
//   - Existing IPs must already be allocated by the source pod.
//   - Sets AlternateOwnerAttrs (unconditionally, to handle back-to-back migrations).
//   - Returns empty routes so CNI skips host-side route programming.
//   - Returns (true, nil) on success, (false, error) if IPs are missing.
func handleVirtLauncherPod(calicoClient client.Interface, handleID string, attrs map[string]string, conf types.NetConf, logger *logrus.Entry, isMigrationTarget bool) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	existingIPs, err := calicoClient.IPAM().IPsByHandle(ctx, handleID)
	if err != nil || len(existingIPs) == 0 {
		if isMigrationTarget {
			// Migration target requires existing IPs allocated by the source pod
			if err != nil {
				logger.WithError(err).Error("Failed to get existing IPs for migration target")
				return false, fmt.Errorf("migration target pod but no IP allocated to VMI handle %s: %w", handleID, err)
			}
			logger.Error("Migration target pod but VMI handle has no allocated IPs")
			return false, fmt.Errorf("migration target pod but no IP allocated to VMI handle %s", handleID)
		}
		// Source pod with no existing IPs - fall through to normal AutoAssign
		if err != nil {
			logger.WithError(err).Debug("No existing IPs for VMI handle, proceeding with new allocation")
		}
		return false, nil
	}

	logger.WithFields(logrus.Fields{
		"ipCount":           len(existingIPs),
		"isMigrationTarget": isMigrationTarget,
	}).Info("Found existing IPs for VMI handle, reusing them")

	// Build result IPs and update owner attributes for each IP
	r := &cniv1.Result{}
	for _, ip := range existingIPs {
		var mask net.IPMask
		if ip.To4() != nil {
			mask = net.CIDRMask(32, 32)
		} else {
			mask = net.CIDRMask(128, 128)
		}
		r.IPs = append(r.IPs, &cniv1.IPConfig{
			Address: net.IPNet{IP: ip.IP, Mask: mask},
		})

		// Source pod: set ActiveOwnerAttrs; Migration target: set AlternateOwnerAttrs
		var updates *ipam.OwnerAttributeUpdates
		if isMigrationTarget {
			updates = &ipam.OwnerAttributeUpdates{
				AlternateOwnerAttrs: attrs,
			}
		} else {
			updates = &ipam.OwnerAttributeUpdates{
				ActiveOwnerAttrs: attrs,
			}
		}
		err = calicoClient.IPAM().SetOwnerAttributes(ctx, ip, handleID, updates, nil)
		if err != nil {
			logger.WithError(err).Errorf("Failed to set owner attributes for IP %s", ip)
			return false, fmt.Errorf("failed to set owner attributes for IP %s: %w", ip, err)
		}
	}

	// Set routes based on pod role:
	// - Source pod: one route per IP so CNI programs host-side routes
	// - Migration target: empty routes to skip route programming (source pod keeps the route
	//   until migration completes, then Felix updates it)
	if isMigrationTarget {
		r.Routes = []*cnitypes.Route{}
		logger.Info("Migration target pod: returning existing IPs with empty routes")
	} else {
		for _, ipConfig := range r.IPs {
			r.Routes = append(r.Routes, &cnitypes.Route{
				Dst: ipConfig.Address,
			})
		}
		logger.Info("Source pod: returning existing IPs with routes")
	}

	return true, cnitypes.PrintResult(r, conf.CNIVersion)
}
