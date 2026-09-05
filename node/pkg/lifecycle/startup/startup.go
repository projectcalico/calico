// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package startup

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
	"github.com/projectcalico/calico/node/pkg/calicoclient"
	"github.com/projectcalico/calico/node/pkg/health"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup/autodetection"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup/autodetection/ipv4"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup/ipclaim"
	"github.com/projectcalico/calico/node/pkg/lifecycle/utils"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

const (
	DEFAULT_IPV4_POOL_CIDR       = "192.168.0.0/16"
	DEFAULT_IPV4_POOL_BLOCK_SIZE = 26
	DEFAULT_IPV6_POOL_BLOCK_SIZE = 122
	DEFAULT_IPV4_POOL_NAME       = "default-ipv4-ippool"
	DEFAULT_IPV6_POOL_NAME       = "default-ipv6-ippool"

	DEFAULT_MONITOR_IP_POLL_INTERVAL = 60 * time.Second

	// ipClaimLeaseTimeout is the Kubernetes API request timeout used only for
	// the IP-claim Lease client built in checkConflictingNodes -- deliberately
	// its own value rather than the 2s timeout used elsewhere in this file for
	// cheap ConfigMap/Node gets. A mass scale-up or fleet reboot, the exact
	// scenario the Lease-based claim exists to survive, is also when apiserver
	// latency is most likely to be degraded; a too-tight timeout there misreads
	// ordinary slowness as a real IP conflict and crash-loops nodes that should
	// just retry (see also ipclaim.ClaimNodeIPLease's own bounded retry).
	ipClaimLeaseTimeout = 10 * time.Second

	// KubeadmConfigConfigMap is defined in k8s.io/kubernetes, which we can't import due to versioning issues.
	KubeadmConfigConfigMap = "kubeadm-config"
	// Rancher clusters store their state in this config map in the kube-system namespace.
	RancherStateConfigMap = "full-cluster-state"

	OSTypeLinux   = "lin"
	OSTypeWindows = "win"
)

var (
	// Default values, names for different configs.
	defaultLogSeverity        = "Info"
	globalFelixConfigName     = "default"
	felixNodeConfigNamePrefix = "node."
	globalBGPConfigName       = "default"
	globalIPAMConfigName      = "default"
)

type runConf struct {
	bailOutAfterUpgrade bool
}

type RunOpt func(*runConf)

// WithBailOutAfterUpgrade is a RunOpt that configures whether to exit after
// performing any required datastore upgrade.  Useful for tests!
func WithBailOutAfterUpgrade(bail bool) RunOpt {
	return func(c *runConf) {
		c.bailOutAfterUpgrade = bail
	}
}

// Run contains the main startup processing for the calico/node.  This
// includes:
//   - Detecting IP address and Network to use for BGP
//   - Configuring the node resource with IP/AS information provided in the
//     environment, or autodetected.
//   - Creating default IP Pools for quick-start use
func Run(opts ...RunOpt) {
	var conf runConf
	for _, opt := range opts {
		opt(&conf)
	}

	// Check $CALICO_STARTUP_LOGLEVEL to capture early log statements
	ConfigureLogging()

	// Determine the name for this node.
	nodeName := utils.DetermineNodeName()
	log.Infof("Starting node %s with version %s", nodeName, buildinfo.Version)

	// Create the Calico API cli.
	cfg, cli := calicoclient.CreateClient()

	ctx := context.Background()

	// An explicit value of true is required to wait for the datastore.
	if os.Getenv("WAIT_FOR_DATASTORE") == "true" {
		waitForConnection(ctx, cli)
		log.Info("Datastore is ready")
	} else {
		log.Info("Skipping datastore connection test")
	}

	// Make sure that this host's BlockAffinity resources are upgraded to add
	// labels for efficient lookup.  CNI plugin also does this on the first
	// allocation after upgrade.  Doing it here too handles some corner cases,
	// such as calico-node being downgraded, doing some allocations and then,
	// upgrading again.
	upgradeCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := cli.IPAM().UpgradeHost(upgradeCtx, nodeName); err != nil {
		log.WithError(err).Errorf("Unable to upgrade host's IPAM resources.")
		utils.Terminate()
	}

	if conf.bailOutAfterUpgrade {
		log.Info("Exiting after datastore migration as requested.")
		return
	}

	// Query the current Node resources.  We update our node resource with
	// updated IP data and use the full list of nodes for validation.
	node := getNode(ctx, cli, nodeName)

	var clientset *kubernetes.Clientset
	var kubeadmConfig, rancherState *v1.ConfigMap
	var k8sNode *v1.Node

	// Determine the Kubernetes node name. Default to the Calico node name unless an explicit
	// value is provided.
	k8sNodeName := nodeName
	if nodeRef := os.Getenv("CALICO_K8S_NODE_REF"); nodeRef != "" {
		k8sNodeName = nodeRef
	}

	// If running under kubernetes with secrets to call k8s API
	if config, err := winutils.BuildConfigFromFlags("", os.Getenv("KUBECONFIG")); err == nil {
		// default timeout is 30 seconds, which isn't appropriate for this kind of
		// startup action because network services, like kube-proxy might not be
		// running and we don't want to block the full 30 seconds if they are just
		// a few seconds behind.
		config.Timeout = 2 * time.Second

		// Create the k8s clientset.
		clientset, err = kubernetes.NewForConfig(config)
		if err != nil {
			log.WithError(err).Error("Failed to create clientset")
			return
		}

		// Check if we're running on a kubeadm and/or rancher cluster. Any error other than not finding the respective
		// config map should be serious enough that we ought to stop here and return.
		kubeadmConfig, err = clientset.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(ctx,
			KubeadmConfigConfigMap,
			metav1.GetOptions{})
		if err != nil {
			if kerrors.IsNotFound(err) {
				kubeadmConfig = nil
			} else if kerrors.IsUnauthorized(err) || kerrors.IsForbidden(err) {
				kubeadmConfig = nil
				log.WithError(err).Info("Unauthorized to query kubeadm configmap, assuming not on kubeadm. CIDR detection will not occur.")
			} else {
				log.WithError(err).Error("failed to query kubeadm's config map")
				utils.Terminate()
			}
		}

		rancherState, err = clientset.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(ctx,
			RancherStateConfigMap,
			metav1.GetOptions{})
		if err != nil {
			if kerrors.IsNotFound(err) {
				rancherState = nil
			} else if kerrors.IsUnauthorized(err) || kerrors.IsForbidden(err) {
				kubeadmConfig = nil
				log.WithError(err).Info("Unauthorized to query rancher configmap, assuming not on rancher. CIDR detection will not occur.")
			} else {
				log.WithError(err).Error("failed to query Rancher's cluster state config map")
				utils.Terminate()
			}
		}

		k8sNode, err = clientset.CoreV1().Nodes().Get(ctx, k8sNodeName, metav1.GetOptions{})
		if err != nil {
			log.WithError(err).Error("Failed to read Node from datastore")
			utils.Terminate()
		}
	}

	needsNodeUpdate := configureAndCheckIPAddressSubnets(ctx, cli, node, k8sNode)
	// Configure the node AS number.
	needsNodeUpdate = configureASNumber(node) || needsNodeUpdate
	// Populate a reference to the node based on orchestrator node identifiers.
	needsNodeUpdate = configureNodeRef(node) || needsNodeUpdate
	if needsNodeUpdate {
		// Apply the updated node resource.
		if _, err := CreateOrUpdate(ctx, cli, node); err != nil {
			log.WithError(err).Errorf("Unable to set node resource configuration")
			utils.Terminate()
		}
	}

	// Check expected filesystem
	ensureFilesystemAsExpected()

	// Configure IP Pool configuration.
	configureIPPools(ctx, cli, kubeadmConfig)

	// Set default configuration required for the cluster.
	if err := ensureDefaultConfig(ctx, cfg, cli, node, getOSType(), kubeadmConfig, rancherState); err != nil {
		log.WithError(err).Errorf("Unable to set global default configuration")
		utils.Terminate()
	}

	// Write config files now that we are ready to start other components.
	utils.WriteNodeConfig(nodeName)

	// Tell the user what the name of the node is.
	log.Infof("Using node name: %s", nodeName)

	if err := ensureNetworkForOS(ctx, cli, nodeName); err != nil {
		log.WithError(err).Errorf("Unable to ensure network for os")
		utils.Terminate()
	}
}

// ManageNodeCondition updates the Kubernetes node condition on successful startup and then sleeps forever. It
// waits for Felix and BIRD to be ready before setting the NetworkUnavailable condition to false.
func ManageNodeCondition(done context.Context, timeout time.Duration) error {
	if err := waitForReady(timeout); err != nil {
		log.WithError(err).Error("Calico failed to become ready, continuing anyway")
	}
	if err := MarkNetworkAvailable(); err != nil {
		return err
	}
	<-done.Done()
	return nil
}

func waitForReady(timeout time.Duration) error {
	// Determine which components should be checked for readiness. We don't do any liveness checking here.
	// Do this by checking the contents of /etc/service/enabled.
	checkBIRD := false
	if _, err := os.Stat("/etc/service/enabled/bird/run"); err == nil {
		checkBIRD = true
	}
	checkBIRD6 := false
	if _, err := os.Stat("/etc/service/enabled/bird6/run"); err == nil {
		checkBIRD6 = true
	}

	// Check Felix health if FELIX_HEALTHENABLED is set to true.
	checkFelix := os.Getenv("FELIX_HEALTHENABLED") == "true"

	// Wait for Felix and BIRD to be ready before setting the NetworkUnavailable condition to false.
	//
	// If we don't succeed, continue anyway to be extra paranoid. This should handle the mainline use case of ensuring
	// calico/node is ready before allowing pods to run on the node.
	log.Info("Waiting for Calico to become ready before continuing...")
	to := time.After(timeout)
	for {
		select {
		case <-to:
			return fmt.Errorf("timed out waiting for Calico to become ready")
		default:
			if err := health.RunOutput(checkBIRD, checkBIRD6, checkFelix, false, false, false, 5*time.Minute); err != nil {
				// If we fail to check the health of the components, log the error and continue waiting.
				log.WithField("reason", err.Error()).Warn("Calico is not ready yet, waiting...")
				time.Sleep(1 * time.Second)
				continue
			}

			// success !
			return nil
		}
	}
}

// MarkNetworkAvailable updates the Kubernetes node condition on successful startup.
func MarkNetworkAvailable() error {
	if os.Getenv("CALICO_NETWORKING_BACKEND") == "none" {
		// Calico is not managing networking, so we don't need to set the NetworkUnavailable condition.
		log.Info("Calico is not managing networking, skipping NetworkUnavailable condition update")
		return nil
	}

	k8sNodeName := utils.DetermineNodeName()
	if nodeRef := os.Getenv("CALICO_K8S_NODE_REF"); nodeRef != "" {
		k8sNodeName = nodeRef
	}

	config, err := winutils.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err == nil {
		// Create the k8s clientset.
		config.Timeout = 2 * time.Second
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.WithError(err).Error("Failed to create clientset")
			return err
		}

		// All done. Set NetworkUnavailable to false if using Calico for networking.
		// We do it late in the process to avoid node resource update conflict because setting
		// node condition will trigger node-controller updating node taints.
		err = utils.SetNodeNetworkUnavailableCondition(*clientset, k8sNodeName, false, 30*time.Second)
		if err != nil {
			log.WithError(err).Error("Unable to set NetworkUnavailable to False")
			return err
		}
	} else if clientcmd.IsEmptyConfig(err) && os.Getenv("DATASTORE_TYPE") != "kubernetes" {
		log.Info("Kubernetes configuration not detected; skipping NetworkUnavailable condition update")
	} else {
		log.WithError(err).Error("Failed to build Kubernetes config")
		return err
	}

	// Remove shutdownTS file when everything is done.
	// This indicates Calico node started successfully.
	if err := utils.RemoveShutdownTimestampFile(); err != nil {
		log.WithError(err).Errorf("Unable to remove shutdown timestamp file")
		return err
	}

	log.Info("Calico started successfully")
	return nil
}

func getMonitorPollInterval() time.Duration {
	interval := DEFAULT_MONITOR_IP_POLL_INTERVAL

	if intervalEnv := os.Getenv("AUTODETECT_POLL_INTERVAL"); intervalEnv != "" {
		var err error
		interval, err = time.ParseDuration(intervalEnv)
		if err != nil {
			log.WithError(err).Errorf("error parsing node IP auto-detect polling interval %s", intervalEnv)
			interval = DEFAULT_MONITOR_IP_POLL_INTERVAL
		}
	}

	return interval
}

func configureAndCheckIPAddressSubnets(ctx context.Context, cli client.Interface, node *internalapi.Node, k8sNode *v1.Node) bool {
	ok, err := configureAndCheckIPAddressSubnetsErr(ctx, cli, node, k8sNode)
	if err != nil {
		log.WithError(err).Error("Failed to configure IP addresses")
		utils.Terminate()
	}
	return ok
}

func configureAndCheckIPAddressSubnetsErr(ctx context.Context, cli client.Interface, node *internalapi.Node, k8sNode *v1.Node) (bool, error) {
	// If Calico is running in policy only mode we don't need to write BGP related
	// details to the Node.
	if os.Getenv("CALICO_NETWORKING_BACKEND") == "none" {
		return false, nil
	}
	// Configure and verify the node IP addresses and subnets.
	checkConflicts, err := configureIPsAndSubnets(node, k8sNode, func(incl []string, excl []string, version ...int) ([]autodetection.Interface, error) {
		return autodetection.GetInterfaces(net.Interfaces, incl, excl, version...)
	})
	if err != nil {
		// If this is auto-detection error, do a cleanup before returning
		clearv4 := os.Getenv("IP") == "autodetect"
		clearv6 := os.Getenv("IP6") == "autodetect"
		if node.ResourceVersion != "" {
			// If we're auto-detecting an IP on an existing node and hit an error, clear the previous
			// IP addresses from the node since they are no longer valid.
			clearNodeIPs(ctx, cli, node, clearv4, clearv6)
		}

		return false, fmt.Errorf("failed to configure IP addresses and subnets: %w", err)
	}

	if node.Spec.BGP.IPv4Address == "" && node.Spec.BGP.IPv6Address == "" {
		if os.Getenv("CALICO_NETWORKING_BACKEND") != "none" {
			return false, fmt.Errorf("no IPv4 or IPv6 addresses configured or detected, required for Calico networking")
		}
		log.Info("No IPv4 or IPv6 addresses configured or detected. Some features may not work properly.")
		// Bail here setting BGPSpec to nil (if empty) to pass validation.
		if reflect.DeepEqual(node.Spec.BGP, &internalapi.NodeBGPSpec{}) {
			node.Spec.BGP = nil
		}
		return checkConflicts, nil
	}

	// checkConflictingNodes' Lease-based claim path (see its own doc comment)
	// runs unconditionally on every call only until it has succeeded once in
	// this process -- tracked by leaseBackfilled -- so that a node whose
	// detected address is unchanged from a prior run still backfills a Lease
	// for it at least once after this image rolls out, letting the whole
	// fleet converge to full Lease coverage within one DaemonSet roll instead
	// of never. This function is called both at node startup and, via
	// MonitorIPAddressSubnetsWithContext, from a periodic goroutine (default
	// every 60s) that runs for the lifetime of the process and treats any
	// error it gets back as fatal to the whole calico-node process, not just
	// this check -- so once the one-time backfill has succeeded, repeating
	// the Lease claim on every tick forever (and turning any transient
	// apiserver hiccup into a process-killing error) is not something we
	// want; checkConflictingNodes reverts to gating on addressChanged after
	// that first success, the same as before this behavior was introduced.
	//
	// checkConflicts is passed through as checkConflictingNodes'
	// addressChanged argument both for that post-backfill gating and because
	// checkConflictingNodes isn't only the Lease path -- it falls back to
	// checkConflictingNodesByList, the original full Node List scan, when the
	// legacy-scan override is set or the datastore isn't Kubernetes. That
	// scan is exactly the O(n) per-node / O(n^2) fleet-wide apiserver load
	// this patch exists to eliminate, and unlike the Lease claim it is not a
	// cheap no-op to repeat on an unchanged address, so the fallback scan
	// only ever runs on an address change. DISABLE_NODE_IP_CHECK remains the
	// intentional opt-out for skipping this check entirely.
	if os.Getenv("DISABLE_NODE_IP_CHECK") != "true" {
		v4conflict, v6conflict, err := checkConflictingNodes(ctx, cli.Nodes(), node, k8sNode, checkConflicts)
		if err != nil {
			// If we've auto-detected a new IP address for an existing node that now conflicts, clear the old IP address(es)
			// from the node in the datastore. This frees the address in case it needs to be used for another node.
			clearv4 := (os.Getenv("IP") == "autodetect") && v4conflict
			clearv6 := (os.Getenv("IP6") == "autodetect") && v6conflict
			if node.ResourceVersion != "" {
				clearNodeIPs(ctx, cli, node, clearv4, clearv6)
			}
			return false, fmt.Errorf("conflicting node detected: %w", err)
		}
	}

	return checkConflicts, nil
}

// MonitorIPAddressSubnetsWithContext is the context-aware variant of
// MonitorIPAddressSubnets for use when running as a goroutine in a
// consolidated process.
func MonitorIPAddressSubnetsWithContext(ctx context.Context) error {
	_, cli := calicoclient.CreateClient()
	nodeName := utils.DetermineNodeName()
	pollInterval := getMonitorPollInterval()

	var clientset *kubernetes.Clientset
	var k8sNode *v1.Node
	var node *internalapi.Node

	k8sNodeName := nodeName
	if nodeRef := os.Getenv("CALICO_K8S_NODE_REF"); nodeRef != "" {
		k8sNodeName = nodeRef
	}
	if config, err := winutils.BuildConfigFromFlags("", os.Getenv("KUBECONFIG")); err == nil {
		clientset, err = kubernetes.NewForConfig(config)
		if err != nil {
			return fmt.Errorf("failed to create clientset: %w", err)
		}
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		log.Debugf("Checking node IP address every %v", pollInterval)

		if clientset != nil {
			var err error
			k8sNode, err = clientset.CoreV1().Nodes().Get(ctx, k8sNodeName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to read Node from datastore: %w", err)
			}
		}

		node = getNode(ctx, cli, nodeName)

		updated, err := configureAndCheckIPAddressSubnetsErr(ctx, cli, node, k8sNode)
		if err != nil {
			return err
		}
		if updated {
			for range 3 {
				_, err := CreateOrUpdate(ctx, cli, node)
				if err == nil {
					log.Info("Updated node IP addresses")
					break
				}
				log.WithError(err).Error("Unable to set node resource configuration, retrying...")
			}
		}
	}
}

// configureNodeRef will attempt to discover the cluster type it is running on, check to ensure we
// have not already set it on this Node, and set it if need be.
// Returns true if the node object needs to updated.
func configureNodeRef(node *internalapi.Node) bool {
	orchestrator := "k8s"
	nodeRef := ""

	// Sort out what type of cluster we're running on.
	if nodeRef = os.Getenv("CALICO_K8S_NODE_REF"); nodeRef == "" {
		return false
	}

	node.Spec.OrchRefs = []internalapi.OrchRef{{NodeName: nodeRef, Orchestrator: orchestrator}}
	return true
}

// CreateOrUpdate creates the Node if ResourceVersion is not specified,
// or Update if it's specified.
func CreateOrUpdate(ctx context.Context, client client.Interface, node *internalapi.Node) (*internalapi.Node, error) {
	if node.ResourceVersion != "" {
		return client.Nodes().Update(ctx, node, options.SetOptions{})
	}

	return client.Nodes().Create(ctx, node, options.SetOptions{})
}

func clearNodeIPs(ctx context.Context, client client.Interface, node *internalapi.Node, clearv4, clearv6 bool) {
	if clearv4 {
		log.WithField("IP", node.Spec.BGP.IPv4Address).Info("Clearing out-of-date IPv4 address from this node")
		node.Spec.BGP.IPv4Address = ""
	}
	if clearv6 {
		log.WithField("IP", node.Spec.BGP.IPv6Address).Info("Clearing out-of-date IPv6 address from this node")
		node.Spec.BGP.IPv6Address = ""
	}

	// If the BGP spec is empty, then set it to nil.
	if node.Spec.BGP != nil && reflect.DeepEqual(*node.Spec.BGP, internalapi.NodeBGPSpec{}) {
		node.Spec.BGP = nil
	}

	if clearv4 || clearv6 {
		_, err := client.Nodes().Update(ctx, node, options.SetOptions{})
		if err != nil {
			log.WithError(err).Warnf("Failed to clear node addresses")
		}
	}
}

func ConfigureLogging() {
	// Default to info level logging
	logLevel := log.InfoLevel

	rawLogLevel := os.Getenv("CALICO_STARTUP_LOGLEVEL")
	if rawLogLevel != "" {
		parsedLevel, err := log.ParseLevel(rawLogLevel)
		if err == nil {
			logLevel = parsedLevel
		} else {
			log.WithError(err).Error("Failed to parse log level, defaulting to info.")
		}
	}

	log.SetLevel(logLevel)
	log.Infof("Early log level set to %v", logLevel)
}

// waitForConnection waits for the datastore to become accessible.
func waitForConnection(ctx context.Context, c client.Interface) {
	log.Info("Checking datastore connection")
	for {
		// Query some arbitrary configuration to see if the connection
		// is working.  Getting a specific Node is a good option, even
		// if the Node does not exist.
		_, err := c.Nodes().Get(ctx, "foo", options.GetOptions{})
		// We only care about a couple of error cases, all others would
		// suggest the datastore is accessible.
		if err != nil {
			switch err.(type) {
			case cerrors.ErrorConnectionUnauthorized:
				log.WithError(err).Warn("Connection to the datastore is unauthorized")
				utils.Terminate()
			case cerrors.ErrorDatastoreError:
				log.WithError(err).Info("Hit error connecting to datastore - retry")
				time.Sleep(1000 * time.Millisecond)
				continue
			}
		}

		// We've connected to the datastore - break out of the loop.
		break
	}
	log.Info("Datastore connection verified")
}

// getNode returns the current node configuration. If this node has not yet
// been created, it returns a blank node resource.
func getNode(ctx context.Context, client client.Interface, nodeName string) *internalapi.Node {
	node, err := client.Nodes().Get(ctx, nodeName, options.GetOptions{})
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			log.WithError(err).WithField("Name", nodeName).Info("Unable to query node configuration")
			log.Warn("Unable to access datastore to query node configuration")
			utils.Terminate()
		}

		log.WithField("Name", nodeName).Info("Building new node resource")
		node = internalapi.NewNode()
		node.Name = nodeName
	}

	return node
}

// configureIPsAndSubnets updates the supplied node resource with IP and Subnet
// information to use for BGP.  This returns true if we detect a change in Node IP address.
func configureIPsAndSubnets(node *internalapi.Node, k8sNode *v1.Node, getInterfaces func([]string, []string, ...int) ([]autodetection.Interface, error)) (bool, error) {
	// If the node resource currently has no BGP configuration, add an empty
	// set of configuration as it makes the processing below easier, and we
	// must end up configuring some BGP fields before we complete.
	if node.Spec.BGP == nil {
		log.Info("Initialize BGP data")
		node.Spec.BGP = &internalapi.NodeBGPSpec{}
	}

	oldIpv4 := node.Spec.BGP.IPv4Address
	oldIpv6 := node.Spec.BGP.IPv6Address
	oldInterfaces := node.Spec.Interfaces

	// Determine the autodetection type for IPv4 and IPv6.  Note that we
	// only autodetect IPv4 when it has not been specified.  IPv6 must be
	// explicitly requested using the "autodetect" value.
	//
	// If we aren't auto-detecting then we need to validate the configured
	// value and possibly fix up missing subnet configuration.
	ipv4Env := os.Getenv("IP")
	if ipv4Env == "autodetect" || (ipv4Env == "" && node.Spec.BGP.IPv4Address == "") {
		adm := os.Getenv("IP_AUTODETECTION_METHOD")
		cidr := autodetection.AutoDetectCIDR(adm, 4, k8sNode, getInterfaces)
		if cidr != nil {
			// We autodetected an IPv4 address so update the value in the node.
			node.Spec.BGP.IPv4Address = cidr.String()
		} else if node.Spec.BGP.IPv4Address == "" {
			// No IPv4 address is configured, but we always require one, so exit.
			log.Warn("Couldn't autodetect an IPv4 address. If auto-detecting, choose a different autodetection method. Otherwise provide an explicit address.")
			return false, fmt.Errorf("failed to autodetect an IPv4 address")
		} else {
			// No IPv4 autodetected, but a previous one was configured.
			// Tell the user we are leaving the value unchanged.  We
			// will validate that the IP matches one on the interface.
			log.Warnf("Autodetection of IPv4 address failed, keeping existing value: %s", node.Spec.BGP.IPv4Address)
			validateIP(node.Spec.BGP.IPv4Address)
		}
	} else if ipv4Env == "none" && node.Spec.BGP.IPv4Address != "" {
		log.Infof("Autodetection for IPv4 disabled, keeping existing value: %s", node.Spec.BGP.IPv4Address)
		validateIP(node.Spec.BGP.IPv4Address)
	} else if ipv4Env != "none" {
		if ipv4Env != "" {
			// Attempt to get the local CIDR of ipv4Env
			ipv4CIDROrIP, err := autodetection.GetLocalCIDR(ipv4Env, 4, getInterfaces)
			if err != nil {
				log.Warnf("Attempt to get the local CIDR: %s failed, %s", ipv4Env, err)
			}
			node.Spec.BGP.IPv4Address = parseIPEnvironment("IP", ipv4CIDROrIP, 4)
		}
		validateIP(node.Spec.BGP.IPv4Address)
	}

	ipv6Env := os.Getenv("IP6")
	if ipv6Env == "autodetect" {
		adm := os.Getenv("IP6_AUTODETECTION_METHOD")
		cidr := autodetection.AutoDetectCIDR(adm, 6, k8sNode, getInterfaces)
		if cidr != nil {
			// We autodetected an IPv6 address so update the value in the node.
			node.Spec.BGP.IPv6Address = cidr.String()
		} else if node.Spec.BGP.IPv6Address == "" {
			// No IPv6 address is configured, but we have requested one, so exit.
			log.Warn("Couldn't autodetect an IPv6 address. If auto-detecting, choose a different autodetection method. Otherwise provide an explicit address.")
			return false, fmt.Errorf("failed to autodetect an IPv6 address")
		} else {
			// No IPv6 autodetected, but a previous one was configured.
			// Tell the user we are leaving the value unchanged.  We
			// will validate that the IP matches one on the interface.
			log.Warnf("Autodetection of IPv6 address failed, keeping existing value: %s", node.Spec.BGP.IPv6Address)
			validateIP(node.Spec.BGP.IPv6Address)
		}
	} else if ipv6Env == "none" && node.Spec.BGP.IPv6Address != "" {
		log.Infof("Autodetection for IPv6 disabled, keeping existing value: %s", node.Spec.BGP.IPv6Address)
		validateIP(node.Spec.BGP.IPv6Address)
	} else if ipv6Env != "none" {
		if ipv6Env != "" {
			node.Spec.BGP.IPv6Address = parseIPEnvironment("IP6", ipv6Env, 6)
		}
		validateIP(node.Spec.BGP.IPv6Address)
	}

	var interfaces []autodetection.Interface
	var err error
	if (ipv4Env != "none" && ipv4Env != "") && (ipv6Env == "none" || ipv6Env == "") {
		interfaces, err = getInterfaces(nil, autodetection.DEFAULT_INTERFACES_TO_EXCLUDE, 4)
		if err != nil {
			return false, err
		}
	} else if (ipv6Env != "none" && ipv6Env != "") && (ipv4Env == "none" || ipv4Env == "") {
		interfaces, err = getInterfaces(nil, autodetection.DEFAULT_INTERFACES_TO_EXCLUDE, 6)
		if err != nil {
			return false, err
		}
	} else if (ipv4Env != "none" && ipv4Env != "") && (ipv6Env != "none" && ipv6Env != "") {
		interfaces, err = getInterfaces(nil, autodetection.DEFAULT_INTERFACES_TO_EXCLUDE, 4, 6)
		if err != nil {
			return false, err
		}
	}

	// Sort the interfaces by name so that we have a consistent order on each run
	slices.SortStableFunc(interfaces, func(i, j autodetection.Interface) int {
		return strings.Compare(i.Name, j.Name)
	})

	var nodeInterfaces []internalapi.NodeInterface
	for _, iface := range interfaces {
		nodeInterface := internalapi.NodeInterface{
			Name: iface.Name,
		}
		for _, addr := range iface.Cidrs {
			ip, _, err := cnet.ParseCIDR(addr.String())
			if err != nil {
				return false, err
			}
			nodeInterface.Addresses = append(nodeInterface.Addresses, ip.String())
		}
		nodeInterfaces = append(nodeInterfaces, nodeInterface)
	}
	node.Spec.Interfaces = nodeInterfaces

	// Detect if we've seen the IP address change, and flag that we need to check for conflicting Nodes
	if node.Spec.BGP.IPv4Address != oldIpv4 {
		log.Info("Node IPv4 changed, will check for conflicts")
		return true, nil
	}
	if node.Spec.BGP.IPv6Address != oldIpv6 {
		log.Info("Node IPv6 changed, will check for conflicts")
		return true, nil
	}

	if !reflect.DeepEqual(node.Spec.Interfaces, oldInterfaces) {
		log.Info("Node interfaces changed")
		return true, nil
	}

	return false, nil
}

// fetchAndValidateIPAndNetwork fetches and validates the IP configuration from
// either the environment variables or from the values already configured in the
// node.
func parseIPEnvironment(envName, envValue string, version int) string {
	// To parse the environment (which could be an IP or a CIDR), convert
	// to a JSON string and use the UnmarshalJSON method on the IPNet
	// struct to parse the value.
	ip := &cnet.IPNet{}
	err := ip.UnmarshalJSON([]byte("\"" + envValue + "\""))
	if err != nil || ip.Version() != version {
		log.Warnf("Environment does not contain a valid IPv%d address: %s=%s", version, envName, envValue)
		utils.Terminate()
	}
	log.Infof("Using IPv%d address from environment: %s=%s", ip.Version(), envName, envValue)

	return ip.String()
}

// validateIP checks that the IP address is actually on one of the host
// interfaces and warns if not.
func validateIP(ipn string) {
	// No validation required if no IP address is specified.
	if ipn == "" {
		return
	}

	ipAddr, _, err := cnet.ParseCIDROrIP(ipn)
	if err != nil {
		log.WithError(err).Errorf("Failed to parse autodetected CIDR '%s'", ipn)
		utils.Terminate()
	}

	// Get a complete list of interfaces with their addresses and check if
	// the IP address can be found.
	ifaces, err := autodetection.GetInterfaces(net.Interfaces, nil, nil, ipAddr.Version())
	if err != nil {
		log.WithError(err).Error("Unable to query host interfaces")
		utils.Terminate()
	}
	if len(ifaces) == 0 {
		log.Info("No interfaces found for validating IP configuration")
	}

	for _, i := range ifaces {
		for _, c := range i.Cidrs {
			if ipAddr.Equal(c.IP) {
				log.Debugf("IPv%d address %s discovered on interface %s", ipAddr.Version(), ipAddr.String(), i.Name)
				return
			}
		}
	}
	log.Warnf("Unable to confirm IPv%d address %s is assigned to this host", ipAddr.Version(), ipAddr)
}

func parseBlockSizeEnvironment(envValue string) int {
	i, err := strconv.Atoi(envValue)
	if err != nil {
		log.WithError(err).Error("Unable to convert blocksize to int")
		utils.Terminate()
	}
	return i
}

// validateBlockSize check if blockSize is valid
func validateBlockSize(version int, blockSize int) {
	// 20 to 32 (inclusive) for IPv4 and 116 to 128 (inclusive) for IPv6
	switch version {
	case 4:
		if blockSize < 20 || blockSize > 32 {
			log.Errorf("Invalid blocksize %d for version %d", blockSize, version)
			utils.Terminate()
		}
	case 6:
		if blockSize < 116 || blockSize > 128 {
			log.Errorf("Invalid blocksize %d for version %d", blockSize, version)
			utils.Terminate()
		}
	default:
		log.Errorf("Invalid ip version specified (%d) when validating blocksize", version)
		utils.Terminate()
	}
}

// validateNodeSelector checks if selector is valid
func validateNodeSelector(version int, s string) {
	_, err := selector.Parse(s)
	if err != nil {
		log.Errorf("Invalid node selector '%s' for version %d: %s", s, version, err)
		utils.Terminate()
	}
}

// evaluateENVBool evaluates a passed environment variable
// Returns True if the envVar is defined and set to true.
// Returns False if the envVar is defined and set to false.
// Returns defaultValue in the envVar is not defined.
// An log entry will always be written
func evaluateENVBool(envVar string, defaultValue bool) bool {
	envValue, isSet := os.LookupEnv(envVar)

	if isSet {

		switch strings.ToLower(envValue) {
		case "false", "0", "no", "n", "f":
			log.Infof("%s is %t through environment variable", envVar, false)
			return false
		}
		log.Infof("%s is %t through environment variable", envVar, true)
		return true
	}
	log.Infof("%s is %t (defaulted) through environment variable", envVar, defaultValue)
	return defaultValue
}

// configureASNumber configures the Node resource with the AS number specified
// in the environment, or is a no-op if not specified.
// Returns true if the node object needs to be updated.
func configureASNumber(node *internalapi.Node) bool {
	// If Calico is running in policy only mode we don't need to write BGP related
	// details to the Node.
	if os.Getenv("CALICO_NETWORKING_BACKEND") == "none" {
		return false
	}
	// Extract the AS number from the environment
	asStr := os.Getenv("AS")
	if asStr != "" {
		if asNum, err := numorstring.ASNumberFromString(asStr); err != nil {
			log.WithError(err).Errorf("The AS number specified in the environment (AS=%s) is not valid", asStr)
			utils.Terminate()
		} else {
			log.Infof("Using AS number specified in environment (AS=%s)", asNum)
			node.Spec.BGP.ASNumber = &asNum
			return true
		}
	} else {
		if node.Spec.BGP.ASNumber == nil {
			log.Info("No AS number configured on node resource, using global value")
		} else {
			log.Infof("Using AS number %s configured in node resource", node.Spec.BGP.ASNumber)
		}
	}
	return false
}

// generateIPv6ULAPrefix return a random generated ULA IPv6 prefix as per RFC 4193.  The pool
// is generated from bytes pulled from a secure random source.
func GenerateIPv6ULAPrefix() (string, error) {
	ulaAddr := []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	_, err := cryptorand.Read(ulaAddr[1:6])
	if err != nil {
		return "", err
	}
	ipNet := net.IPNet{
		IP:   net.IP(ulaAddr),
		Mask: net.CIDRMask(48, 128),
	}
	return ipNet.String(), nil
}

// configureIPPools ensures that default IP pools are created (unless explicitly requested otherwise).
func configureIPPools(ctx context.Context, client client.Interface, kubeadmConfig *v1.ConfigMap) {
	// Read in environment variables for use here and later.
	ipv4Pool := os.Getenv("CALICO_IPV4POOL_CIDR")
	ipv6Pool := os.Getenv("CALICO_IPV6POOL_CIDR")

	if strings.ToLower(os.Getenv("NO_DEFAULT_POOLS")) == "true" {
		if len(ipv4Pool) > 0 || len(ipv6Pool) > 0 {
			log.Error("Invalid configuration with NO_DEFAULT_POOLS defined and CALICO_IPV4POOL_CIDR or CALICO_IPV6POOL_CIDR defined.")
			utils.Terminate()
		}

		log.Info("Skipping IP pool configuration")
		return
	}

	var (
		ipv4PoolEnabled = true
		ipv6PoolEnabled = true
	)

	if ipv4Pool == "none" {
		log.Info("Skipping IPv4 pool configuration")

		ipv4PoolEnabled = false
	}

	if ipv6Pool == "none" {
		log.Info("Skipping IPv6 pool configuration")

		ipv6PoolEnabled = false
	}

	// If CIDRs weren't specified through the environment variables, check if they're present in kubeadm's
	// config map.
	if ((ipv4PoolEnabled && len(ipv4Pool) == 0) || (ipv6PoolEnabled && len(ipv6Pool) == 0)) && kubeadmConfig != nil {
		v4, v6, err := extractKubeadmCIDRs(kubeadmConfig)
		if err == nil {
			if ipv4PoolEnabled && len(ipv4Pool) == 0 {
				ipv4Pool = v4
				log.Infof("found v4=%s in the kubeadm config map", ipv4Pool)
			}
			if ipv6PoolEnabled && len(ipv6Pool) == 0 {
				ipv6Pool = v6
				log.Infof("found v6=%s in the kubeadm config map", ipv6Pool)
			}
		} else {
			log.WithError(err).Warn("Failed to extract CIDRs from kubeadm config.")
		}
	}

	var (
		ipv4BlockSize int
		ipv6BlockSize int

		ipv4IpipModeEnvVar, ipv4VXLANModeEnvVar, ipv4BlockSizeEnvVar string
		ipv6VXLANModeEnvVar, ipv6BlockSizeEnvVar                     string

		ipv4NodeSelector string
		ipv6NodeSelector string

		ipv4Cidr *cnet.IPNet
		ipv6Cidr *cnet.IPNet

		err error
	)

	if ipv4PoolEnabled {
		ipv4IpipModeEnvVar = strings.ToLower(os.Getenv("CALICO_IPV4POOL_IPIP"))
		ipv4VXLANModeEnvVar = strings.ToLower(os.Getenv("CALICO_IPV4POOL_VXLAN"))

		ipv4BlockSizeEnvVar = os.Getenv("CALICO_IPV4POOL_BLOCK_SIZE")
		if ipv4BlockSizeEnvVar != "" {
			ipv4BlockSize = parseBlockSizeEnvironment(ipv4BlockSizeEnvVar)
		} else {
			ipv4BlockSize = DEFAULT_IPV4_POOL_BLOCK_SIZE
		}

		validateBlockSize(4, ipv4BlockSize)

		ipv4NodeSelector = os.Getenv("CALICO_IPV4POOL_NODE_SELECTOR")
		validateNodeSelector(4, ipv4NodeSelector)

		// Read IPV4 CIDR from env if set and parse then check it for errors
		if ipv4Pool == "" {
			ipv4Pool = DEFAULT_IPV4_POOL_CIDR

			_, preferedNet, _ := net.ParseCIDR(DEFAULT_IPV4_POOL_CIDR)
			if selectedPool, err := ipv4.GetDefaultIPv4Pool(preferedNet); err == nil {
				ipv4Pool = selectedPool.String()
			}

			log.Infof("Selected default IP pool is '%s'", ipv4Pool)
		}
		_, ipv4Cidr, err = cnet.ParseCIDR(ipv4Pool)
		if err != nil || ipv4Cidr.Version() != 4 {
			log.Errorf("Invalid CIDR specified in CALICO_IPV4POOL_CIDR '%s'", ipv4Pool)
			utils.Terminate()
			return // not really needed but allows testing to function
		}
	}

	if ipv6PoolEnabled {
		ipv6VXLANModeEnvVar = strings.ToLower(os.Getenv("CALICO_IPV6POOL_VXLAN"))

		ipv6BlockSizeEnvVar = os.Getenv("CALICO_IPV6POOL_BLOCK_SIZE")
		if ipv6BlockSizeEnvVar != "" {
			ipv6BlockSize = parseBlockSizeEnvironment(ipv6BlockSizeEnvVar)
		} else {
			ipv6BlockSize = DEFAULT_IPV6_POOL_BLOCK_SIZE
		}

		validateBlockSize(6, ipv6BlockSize)

		ipv6NodeSelector = os.Getenv("CALICO_IPV6POOL_NODE_SELECTOR")
		validateNodeSelector(6, ipv6NodeSelector)

		// If no IPv6 pool is specified, generate one.
		if ipv6Pool == "" {
			ipv6Pool, err = GenerateIPv6ULAPrefix()
			if err != nil {
				log.Errorf("Failed to generate an IPv6 default pool")
				utils.Terminate()
			}
		}
		_, ipv6Cidr, err = cnet.ParseCIDR(ipv6Pool)
		if err != nil || ipv6Cidr.Version() != 6 {
			log.Errorf("Invalid CIDR specified in CALICO_IPV6POOL_CIDR '%s'", ipv6Pool)
			utils.Terminate()
			return // not really needed but allows testing to function
		}
	}

	// Get a list of all IP Pools
	poolList, err := client.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Error("Unable to fetch IP pool list")
		utils.Terminate()
		return // not really needed but allows testing to function
	}

	// Check for IPv4 and IPv6 pools.
	ipv4Present := false
	ipv6Present := false
	for _, p := range poolList.Items {
		ip, _, err := cnet.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			log.Warnf("Error parsing CIDR '%s'. Skipping the IPPool.", p.Spec.CIDR)
			continue
		}
		version := ip.Version()
		ipv4Present = ipv4Present || (version == 4)
		ipv6Present = ipv6Present || (version == 6)
		if ipv4Present && ipv6Present {
			break
		}
	}

	// Ensure there are pools created for each IP version.
	if ipv4PoolEnabled && !ipv4Present {
		log.Debug("Create default IPv4 IP pool")
		outgoingNATEnabled := evaluateENVBool("CALICO_IPV4POOL_NAT_OUTGOING", true)
		bgpExportDisabled := evaluateENVBool("CALICO_IPV4POOL_DISABLE_BGP_EXPORT", false)

		createIPPool(ctx, client, ipv4Cidr, DEFAULT_IPV4_POOL_NAME, ipv4IpipModeEnvVar, ipv4VXLANModeEnvVar, outgoingNATEnabled, ipv4BlockSize, ipv4NodeSelector, bgpExportDisabled)
	}

	if ipv6PoolEnabled && !ipv6Present && ipv6Supported() {
		log.Debug("Create default IPv6 IP pool")
		outgoingNATEnabled := evaluateENVBool("CALICO_IPV6POOL_NAT_OUTGOING", false)
		bgpExportDisabled := evaluateENVBool("CALICO_IPV6POOL_DISABLE_BGP_EXPORT", false)

		createIPPool(ctx, client, ipv6Cidr, DEFAULT_IPV6_POOL_NAME, string(api.IPIPModeNever), ipv6VXLANModeEnvVar, outgoingNATEnabled, ipv6BlockSize, ipv6NodeSelector, bgpExportDisabled)
	}
}

// createIPPool creates an IP pool using the specified CIDR.  This
// method is a no-op if the pool already exists.
func createIPPool(ctx context.Context, client client.Interface, cidr *cnet.IPNet, poolName, ipipModeName, vxlanModeName string, isNATOutgoingEnabled bool, blockSize int, nodeSelector string, bgpExportDisabled bool) {
	version := cidr.Version()
	var ipipMode api.IPIPMode
	var vxlanMode api.VXLANMode

	// Parse the given IPIP mode.
	switch strings.ToLower(ipipModeName) {
	case "", "off", "never":
		ipipMode = api.IPIPModeNever
	case "crosssubnet", "cross-subnet":
		ipipMode = api.IPIPModeCrossSubnet
	case "always":
		ipipMode = api.IPIPModeAlways
	default:
		log.Errorf("Unrecognized IPIP mode specified in CALICO_IPV4POOL_IPIP '%s'", ipipModeName)
		utils.Terminate()
	}

	// Parse the given VXLAN mode.
	switch strings.ToLower(vxlanModeName) {
	case "", "off", "never":
		vxlanMode = api.VXLANModeNever
	case "crosssubnet", "cross-subnet":
		vxlanMode = api.VXLANModeCrossSubnet
	case "always":
		vxlanMode = api.VXLANModeAlways
	default:
		log.Errorf("Unrecognized VXLAN mode specified in CALICO_IPV%dPOOL_VXLAN '%s'", version, vxlanModeName)
		utils.Terminate()
	}

	pool := &api.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: poolName,
		},
		Spec: api.IPPoolSpec{
			CIDR:             cidr.String(),
			NATOutgoing:      isNATOutgoingEnabled,
			IPIPMode:         ipipMode,
			VXLANMode:        vxlanMode,
			BlockSize:        blockSize,
			NodeSelector:     nodeSelector,
			DisableBGPExport: bgpExportDisabled,
		},
	}

	log.Infof("Ensure default IPv%d pool is created. IPIP mode: %s, VXLAN mode: %s, DisableBGPExport: %t", version, ipipMode, vxlanMode, bgpExportDisabled)

	// Create the pool.  There is a small chance that another node may
	// beat us to it, so handle the fact that the pool already exists.
	if _, err := client.IPPools().Create(ctx, pool, options.SetOptions{}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceAlreadyExists); !ok {
			log.WithError(err).Errorf("Failed to create default IPv%d IP pool: %s", version, cidr.String())
			utils.Terminate()
		}
	} else {
		log.Infof("Created default IPv%d pool (%s) with NAT outgoing %t. IPIP mode: %s, VXLAN mode: %s, DisableBGPExport: %t",
			version, cidr, isNATOutgoingEnabled, ipipMode, vxlanMode, bgpExportDisabled)
	}
}

// newIPClaimClientset builds the Kubernetes clientset checkConflictingNodes
// uses to claim/release the IP-claim Lease. A package variable rather than a
// direct call, so tests can substitute a fake clientset instead of requiring
// real in-cluster/kubeconfig credentials -- the same seam pattern
// claimRetryAttempts/claimRetryBackoff use in the ipclaim package.
var newIPClaimClientset = func() (kubernetes.Interface, error) {
	kubeConfig, err := winutils.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		return nil, fmt.Errorf("no in-cluster/kubeconfig credentials available: %w", err)
	}
	kubeConfig.Timeout = ipClaimLeaseTimeout
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build Kubernetes clientset: %w", err)
	}
	return clientset, nil
}

// ipClaimClientsetMu guards ipClaimClientset, memoizing the clientset
// newIPClaimClientset builds so parsing kubeconfig/in-cluster credentials and
// TLS certificates happens once per process instead of on every
// checkConflictingNodes call -- this compounds with the Lease-claim path now
// running on every startup (see configureAndCheckIPAddressSubnetsErr), so
// without memoization a stable, unchanging address would still rebuild a
// whole clientset on every backfill attempt.
//
// A mutex-guarded "built successfully yet" check, not sync.Once: sync.Once.Do
// runs its function exactly once per process regardless of whether it errors,
// which would permanently cache a transient build failure (e.g. credentials
// not yet available at boot) and hand every later call -- including from the
// periodic monitor-addresses goroutine, which Fatals the process on any
// returned error -- the same cached error forever, with no chance to ever
// succeed and close the leaseBackfilled gate. Only a successful build is
// memoized; a failed build is retried on the next call.
//
// Package-level, not local to getIPClaimClientset, so a test can reset it
// between subtests: each subtest substitutes newIPClaimClientset with its own
// fake and expects its own call count, which a cached value surviving from a
// prior subtest would break.
var (
	ipClaimClientsetMu sync.Mutex
	ipClaimClientset   kubernetes.Interface
)

// getIPClaimClientset returns the memoized Kubernetes clientset for the IP
// claim Lease, building it via newIPClaimClientset on first use and on every
// subsequent call until a build succeeds. Once a build succeeds, the result
// is cached for the rest of the process and newIPClaimClientset is never
// called again.
func getIPClaimClientset() (kubernetes.Interface, error) {
	ipClaimClientsetMu.Lock()
	defer ipClaimClientsetMu.Unlock()
	if ipClaimClientset != nil {
		return ipClaimClientset, nil
	}
	clientset, err := newIPClaimClientset()
	if err != nil {
		return nil, err
	}
	ipClaimClientset = clientset
	return ipClaimClientset, nil
}

// leaseBackfilled tracks whether checkConflictingNodes' Lease-based claim
// path has completed a claim successfully at least once in this process. It
// is set only on success (not merely attempted), so a real failure keeps
// retrying on every subsequent call until it eventually succeeds once. See
// configureAndCheckIPAddressSubnetsErr for why this one-time-success gate
// exists: it lets a stable node backfill its Lease once per process without
// re-running the claim on every periodic-monitor tick forever afterward.
var leaseBackfilled atomic.Bool

// releaseStaleIPClaimLeases attempts to release the IP-claim Leases for a
// node's previous IPv4/IPv6 addresses -- releaseIPv4/releaseIPv6 as computed
// by checkConflictingNodes' diagnostic prior-address comparison. It is the
// single shared implementation of that release attempt, called from every
// return path in checkConflictingNodes that has a stale address to release:
// the main Lease-claim path and all three of its legacy-scan fallback
// branches (ForceLegacyScan, a LoadClientConfig error, and a non-Kubernetes
// datastore type).
//
// This is best-effort and never fails the caller. Building the clientset can
// fail here too -- most notably from the fallback branches, which are
// explicitly choosing not to depend on Kubernetes-Lease functionality being
// available (a LoadClientConfig error or a non-Kubernetes Calico datastore
// says nothing about whether the underlying Kubernetes cluster's own API is
// reachable, so it's still worth trying, but a failure to reach it must not
// block the legacy-scan conflict check those branches exist to run). A
// clientset build failure is logged as a warning and treated as a no-op,
// exactly like an individual ReleaseNodeIPLease failure below.
// ReleaseNodeIPLease itself is safe to call unconditionally: it re-reads the
// Lease and only deletes it if this node is still its HolderIdentity,
// deleting with a UID+ResourceVersion precondition tied to that exact read,
// so it can never take down a different node's live claim.
func releaseStaleIPClaimLeases(ctx context.Context, nodeName string, releaseIPv4, releaseIPv6 net.IP) {
	if releaseIPv4 == nil && releaseIPv6 == nil {
		return
	}
	clientset, err := getIPClaimClientset()
	if err != nil {
		log.WithError(err).Warnf("Failed to build Kubernetes clientset to release stale IP claim lease(s) for %q; they will not be retried this run", nodeName)
		return
	}
	if releaseIPv4 != nil {
		if rerr := ipclaim.ReleaseNodeIPLease(ctx, clientset, nodeName, releaseIPv4); rerr != nil {
			log.WithError(rerr).Warnf("Failed to release the stale IP claim lease for our previous IPv4 address %s; it will not be retried this run", releaseIPv4)
		}
	}
	if releaseIPv6 != nil {
		if rerr := ipclaim.ReleaseNodeIPLease(ctx, clientset, nodeName, releaseIPv6); rerr != nil {
			log.WithError(rerr).Warnf("Failed to release the stale IP claim lease for our previous IPv6 address %s; it will not be retried this run", releaseIPv6)
		}
	}
}

// checkConflictingNodes checks whether any other nodes have been configured
// with the same IP addresses.
// checkConflictingNodes claims our detected IP addresses and reports a
// conflict if another node already holds them.
//
// This claims via a Kubernetes Lease named after the IP rather than listing
// every Calico Node and scanning client-side. Lease creation is atomic at the
// API server (an etcd CreateRevision==0 guard), so two nodes racing to claim
// the same IP never both succeed -- the loser gets AlreadyExists, which is
// treated as a real conflict. The previous implementation ran a full Node
// List on every node whose detected IP changed; under a mass scale-up or
// reboot that is O(n) apiserver load times n nodes doing it concurrently,
// i.e. O(n^2), and was a confirmed contributor to Calico control-plane
// overload at scale.
//
// The Lease path needs a Kubernetes API to claim against, so it only applies
// when running under the Kubernetes datastore driver -- the actual resolved
// Calico datastore type (apiconfig.LoadClientConfig), not merely "were
// in-cluster/kubeconfig credentials loadable". A calico-node DaemonSet
// running with DATASTORE_TYPE=etcdv3 still has a normal in-cluster
// ServiceAccount mounted, so that alone would build a kubeconfig
// successfully and can't tell KDD and etcd apart. On an etcd-backed
// deployment there is no Kubernetes-datastore API to claim a Lease against,
// and checkConflictingNodesByList (the original scan) is used instead.
//
// nodes takes the narrow client.NodeInterface rather than the full
// client.Interface -- this is the only part of the Calico client this
// function (and checkConflictingNodesByList) ever uses, and it's what makes
// the gating/wiring logic here unit-testable with a hand-written fake: the
// full client.Interface pulls in dozens of unrelated resource-client
// methods that a fake would otherwise have to implement for no reason.
//
// addressChanged is the caller's checkConflicts value -- whether
// configureIPsAndSubnets detected our address changed since the last
// startup. The Lease-based claim above runs regardless of addressChanged
// only until it has succeeded once in this process -- see leaseBackfilled --
// after which it, too, only runs when addressChanged is true, the same as
// checkConflictingNodesByList always has. Before that first success it's a
// cheap, idempotent no-op when we already hold the Lease, and needs to run
// on every call so an already-stable node backfills its Lease; after that
// first success, repeating it on every call forever (including from the
// periodic monitor goroutine, which treats any error as fatal to the whole
// process) is unnecessary load and unnecessary fragility for no benefit. The
// checkConflictingNodesByList fallback branches are different regardless --
// that's the original O(n) full Node List scan, not a cheap no-op, so each
// of those branches only ever runs it when addressChanged is true, same as
// the pre-Lease behavior. When addressChanged is false and a fallback branch
// would otherwise have run the scan, it's skipped and (false, false, nil) is
// returned instead. When addressChanged is true and a fallback branch does
// run the scan, it first calls releaseStaleIPClaimLeases so a stale Lease
// from a previous address is still attempted, exactly as the main Lease-claim
// path does below -- see releaseStaleIPClaimLeases and its callers.
func checkConflictingNodes(ctx context.Context, nodes client.NodeInterface, node *internalapi.Node, k8sNode *v1.Node, addressChanged bool) (v4conflict, v6conflict bool, retErr error) {
	ourIPv4, _, err := cnet.ParseCIDROrIP(node.Spec.BGP.IPv4Address)
	if err != nil && node.Spec.BGP.IPv4Address != "" {
		log.WithError(err).Errorf("Error parsing IPv4 CIDR '%s' for node '%s'", node.Spec.BGP.IPv4Address, node.Name)
		retErr = err
		return
	}
	ourIPv6, _, err := cnet.ParseCIDROrIP(node.Spec.BGP.IPv6Address)
	if err != nil && node.Spec.BGP.IPv6Address != "" {
		log.WithError(err).Errorf("Error parsing IPv6 CIDR '%s' for node '%s'", node.Spec.BGP.IPv6Address, node.Name)
		retErr = err
		return
	}

	// Diagnostic only, and cheap: a single targeted Get on our own prior
	// record (not the full-cluster List the conflict check itself used to
	// do) to warn if our IP changed since last time, which could indicate
	// two nodes sharing a name. Not an error condition on its own when
	// addressChanged is false, since nothing new is being committed this run
	// in that case. A NotFound here is expected for a brand-new node with no
	// prior record and isn't worth a warning; any other error is logged so a
	// Forbidden/RBAC-denied or otherwise unexpected failure doesn't disappear
	// silently.
	//
	// When addressChanged is true, though, this Get is the only source of
	// truth for what the prior address was: it's what releaseIPv4/releaseIPv6
	// below are computed from. If it fails here with anything other than
	// ErrorResourceDoesNotExist and we pressed on anyway, the caller would go
	// on to claim and persist the new address this run with nothing marking
	// that the prior-address diagnostic never actually ran -- and once the
	// node record is overwritten with the new address, that prior address is
	// gone for good and its Lease can never be identified and released again.
	// So in that case this is treated as fatal: return the error, let the
	// caller propagate it without persisting anything, and let the whole
	// check retry (next startup, or after the process is restarted) once the
	// Get can succeed and the true prior address is still derivable.
	//
	// This also gives us the previous address(es), if any, so that once
	// we've handled the new address below we can release the stale Lease for
	// the old one -- see ipclaim.ReleaseNodeIPLease. The Node object itself
	// hasn't been deleted here (it's the same node, just a new or now-absent
	// address), so the old Lease's OwnerReference-based GC never fires on its
	// own. A prior address is released not only when it changed to a
	// different address, but also when it disappeared entirely (e.g. the
	// interface that provided it went away): either way the old Lease is no
	// longer backed by a live address on this node and would otherwise leak
	// until the Node object itself is deleted.
	//
	// Whether that release happens below is independent of whether the new
	// address's own claim conflicts with another node: releaseIPv4/releaseIPv6
	// are computed purely from this node's own prior-vs-current address, and
	// gating the release on the new address's claim result would leave the
	// old Lease orphaned whenever the new address genuinely conflicts. That
	// matters because a persistent conflict on an autodetected address makes
	// the caller clear this node's own stored BGP address and the process
	// then restarts; on the next run there is no prior address left to diff
	// against, so the release could never be computed again and the old
	// Lease would never be freed. ReleaseNodeIPLease is safe to call
	// unconditionally here: it re-reads the Lease and only deletes it if this
	// node is still its HolderIdentity, deleting with a UID+ResourceVersion
	// precondition tied to that exact read, so it can never take down a
	// different node's live claim.
	//
	// This release attempt is genuinely unconditional across every return
	// path below that has a stale address to release, not merely the main
	// Lease-claim path: each of the three legacy-scan fallback branches
	// (ForceLegacyScan, a LoadClientConfig error, and a non-Kubernetes
	// datastore type) also calls releaseStaleIPClaimLeases before falling
	// back to checkConflictingNodesByList, since those branches choosing not
	// to use the Lease-based claim for the new address says nothing about
	// whether a stale Lease from a previous address still needs cleaning up.
	// See releaseStaleIPClaimLeases.
	var releaseIPv4, releaseIPv6 net.IP
	prior, gerr := nodes.Get(ctx, node.Name, options.GetOptions{})
	if gerr != nil {
		if _, ok := gerr.(cerrors.ErrorResourceDoesNotExist); !ok {
			if addressChanged {
				log.WithError(gerr).Errorf("Failed to read our own prior node record %q for the IP-change diagnostic; refusing to claim and persist the new address this run so the prior address isn't lost", node.Name)
				retErr = gerr
				return
			}
			log.WithError(gerr).Warnf("Failed to read our own prior node record %q for the IP-change diagnostic; skipping stale IP claim lease release detection this run", node.Name)
		}
	} else if prior.Spec.BGP != nil {
		if priorIPv4, _, perr := cnet.ParseCIDROrIP(prior.Spec.BGP.IPv4Address); perr == nil &&
			priorIPv4.IP != nil && (ourIPv4.IP == nil || !priorIPv4.Equal(ourIPv4.IP)) {
			if ourIPv4.IP != nil {
				fields := log.Fields{"node": node.Name, "original": priorIPv4.String(), "updated": ourIPv4.String()}
				log.WithFields(fields).Warnf("IPv4 address has changed. This could happen if there are multiple nodes with the same name.")
			} else {
				log.WithFields(log.Fields{"node": node.Name, "original": priorIPv4.String()}).Warnf("IPv4 address is no longer detected; releasing its IP claim lease.")
			}
			releaseIPv4 = priorIPv4.IP
		}
		if priorIPv6, _, perr := cnet.ParseCIDROrIP(prior.Spec.BGP.IPv6Address); perr == nil &&
			priorIPv6.IP != nil && (ourIPv6.IP == nil || !priorIPv6.Equal(ourIPv6.IP)) {
			if ourIPv6.IP != nil {
				fields := log.Fields{"node": node.Name, "original": priorIPv6.String(), "updated": ourIPv6.String()}
				log.WithFields(fields).Warnf("IPv6 address has changed. This could happen if there are multiple nodes with the same name.")
			} else {
				log.WithFields(log.Fields{"node": node.Name, "original": priorIPv6.String()}).Warnf("IPv6 address is no longer detected; releasing its IP claim lease.")
			}
			releaseIPv6 = priorIPv6.IP
		}
	}

	// See ipclaim.ForceLegacyScanEnvVar: a rollout safety valve so operators
	// can revert to the pre-Lease behavior without a full patch rollback or
	// image rebuild if the Lease-based claim misbehaves in production.
	// Independent of DISABLE_NODE_IP_CHECK, which skips the conflict check
	// entirely; this instead forces a specific implementation of the check to
	// still run.
	if ipclaim.ForceLegacyScan() {
		if !addressChanged {
			return false, false, nil
		}
		log.Infof("%s is set; using the legacy full-list IP conflict scan instead of the Lease-based claim", ipclaim.ForceLegacyScanEnvVar)
		releaseStaleIPClaimLeases(ctx, node.Name, releaseIPv4, releaseIPv6)
		return checkConflictingNodesByList(ctx, nodes, node, ourIPv4, ourIPv6)
	}

	cfg, cerr := apiconfig.LoadClientConfig("")
	if cerr != nil {
		if !addressChanged {
			return false, false, nil
		}
		log.WithError(cerr).Error("Failed to determine the Calico datastore type; using the legacy full-list IP conflict scan")
		releaseStaleIPClaimLeases(ctx, node.Name, releaseIPv4, releaseIPv6)
		return checkConflictingNodesByList(ctx, nodes, node, ourIPv4, ourIPv6)
	}
	if cfg.Spec.DatastoreType != apiconfig.Kubernetes {
		if !addressChanged {
			return false, false, nil
		}
		releaseStaleIPClaimLeases(ctx, node.Name, releaseIPv4, releaseIPv6)
		return checkConflictingNodesByList(ctx, nodes, node, ourIPv4, ourIPv6)
	}

	// The one-time backfill gate: once the Lease-based claim has succeeded
	// once in this process, treat it the same as the legacy-scan fallback
	// branches above and only run it again when the address actually
	// changed. See leaseBackfilled and this function's addressChanged
	// doc paragraph.
	if !addressChanged && leaseBackfilled.Load() {
		return false, false, nil
	}

	clientset, err := getIPClaimClientset()
	if err != nil {
		log.WithError(err).Error("Failed to build Kubernetes clientset for IP claim lease")
		retErr = err
		return
	}

	if ourIPv4.IP != nil {
		conflict, holder, err := ipclaim.ClaimNodeIPLease(ctx, clientset, k8sNode, node.Name, ourIPv4.IP)
		if err != nil {
			retErr = err
			return
		}
		if conflict {
			log.Warnf("Calico node '%s' is already using the IPv4 address %s.", holder, ourIPv4.String())
			v4conflict = true
			retErr = fmt.Errorf("IPv4 address conflict")
		}
	}

	if ourIPv6.IP != nil {
		conflict, holder, err := ipclaim.ClaimNodeIPLease(ctx, clientset, k8sNode, node.Name, ourIPv6.IP)
		if err != nil {
			retErr = err
			return
		}
		if conflict {
			log.Warnf("Calico node '%s' is already using the IPv6 address %s.", holder, ourIPv6.String())
			v6conflict = true
			retErr = fmt.Errorf("IPv6 address conflict")
		}
	}

	releaseStaleIPClaimLeases(ctx, node.Name, releaseIPv4, releaseIPv6)

	if retErr == nil {
		leaseBackfilled.Store(true)
	}
	return
}

// checkConflictingNodesByList is the pre-Lease conflict-detection strategy:
// list every Calico Node and scan client-side for an IP match. Kept as the
// fallback for etcd-backed deployments, where there is no Kubernetes API to
// claim a Lease against; see checkConflictingNodes.
func checkConflictingNodesByList(ctx context.Context, nodes client.NodeInterface, node *internalapi.Node, ourIPv4, ourIPv6 *cnet.IP) (v4conflict, v6conflict bool, retErr error) {
	var allNodes []internalapi.Node
	if nodeList, err := nodes.List(ctx, options.ListOptions{}); err != nil {
		log.WithError(err).Errorf("Unable to query node configuration")
		retErr = err
		return
	} else {
		allNodes = nodeList.Items
	}

	for _, theirNode := range allNodes {
		if theirNode.Spec.BGP == nil || theirNode.Name == node.Name {
			// Skip nodes that don't have BGP configured (we know this node
			// does, since we only perform this check after configuring BGP),
			// and skip ourselves -- checkConflictingNodes already handled the
			// "did our own IP change" diagnostic via a targeted Get.
			continue
		}

		theirIPv4, _, err := cnet.ParseCIDROrIP(theirNode.Spec.BGP.IPv4Address)
		if err != nil && theirNode.Spec.BGP.IPv4Address != "" {
			log.WithError(err).Errorf("Error parsing IPv4 CIDR '%s' for node '%s'", theirNode.Spec.BGP.IPv4Address, theirNode.Name)
			retErr = err
			return
		}

		theirIPv6, _, err := cnet.ParseCIDROrIP(theirNode.Spec.BGP.IPv6Address)
		if err != nil && theirNode.Spec.BGP.IPv6Address != "" {
			log.WithError(err).Errorf("Error parsing IPv6 CIDR '%s' for node '%s'", theirNode.Spec.BGP.IPv6Address, theirNode.Name)
			retErr = err
			return
		}

		// Check that other nodes aren't using the same IP addresses.
		// This is an error condition.
		if theirIPv4.IP != nil && ourIPv4.IP != nil && theirIPv4.Equal(ourIPv4.IP) {
			log.Warnf("Calico node '%s' is already using the IPv4 address %s.", theirNode.Name, ourIPv4.String())
			retErr = fmt.Errorf("IPv4 address conflict")
			v4conflict = true
		}

		if theirIPv6.IP != nil && ourIPv6.IP != nil && theirIPv6.Equal(ourIPv6.IP) {
			log.Warnf("Calico node '%s' is already using the IPv6 address %s.", theirNode.Name, ourIPv6.String())
			retErr = fmt.Errorf("IPv6 address conflict")
			v6conflict = true
		}
	}
	return
}

// ensureDefaultConfig ensures all of the required default settings are configured.
func ensureDefaultConfig(
	ctx context.Context,
	cfg *apiconfig.CalicoAPIConfig,
	c client.Interface,
	node *internalapi.Node,
	osType string,
	kubeadmConfig,
	rancherState *v1.ConfigMap,
) error {
	// Ensure the ClusterInformation is populated.
	// Get the ClusterType from ENV var. This is set from the manifest.
	clusterType := os.Getenv("CLUSTER_TYPE")

	if kubeadmConfig != nil {
		if len(clusterType) == 0 {
			clusterType = "kubeadm"
		} else {
			clusterType += ",kubeadm"
		}
	}

	if rancherState != nil {
		if len(clusterType) == 0 {
			clusterType = "rancher"
		} else {
			clusterType += ",rancher"
		}
	}

	if osType != OSTypeLinux {
		if len(clusterType) == 0 {
			clusterType = osType
		} else {
			clusterType += "," + osType
		}
	}

	if err := c.EnsureInitialized(ctx, buildinfo.Version, clusterType); err != nil {
		return err
	}

	// By default we set the global reporting interval to 0 - this is
	// different from the defaults defined in Felix.
	//
	// Logging to file is disabled in the felix.cfg config file.  This
	// should always be disabled for calico/node.  By default we log to
	// screen - set the default logging value that we desire.
	felixConf, err := c.FelixConfigurations().Get(ctx, globalFelixConfigName, options.GetOptions{})
	if err != nil {
		// Create the default config if it doesn't already exist.
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			newFelixConf := api.NewFelixConfiguration()
			newFelixConf.Name = globalFelixConfigName
			newFelixConf.Spec.ReportingInterval = &metav1.Duration{Duration: 0}
			newFelixConf.Spec.LogSeverityScreen = defaultLogSeverity
			_, err = c.FelixConfigurations().Create(ctx, newFelixConf, options.SetOptions{})
			if err != nil {
				if conflict, ok := err.(cerrors.ErrorResourceAlreadyExists); ok {
					log.Infof("Ignoring conflict when setting value %s", conflict.Identifier)
				} else {
					log.WithError(err).WithField("FelixConfig", newFelixConf).Errorf("Error creating Felix global config")
					return err
				}
			}
		} else {
			log.WithError(err).WithField("FelixConfig", globalFelixConfigName).Errorf("Error getting Felix global config")
			return err
		}
	} else {
		updateNeeded := false
		if felixConf.Spec.ReportingInterval == nil {
			felixConf.Spec.ReportingInterval = &metav1.Duration{Duration: 0}
			updateNeeded = true
		} else {
			log.WithField("ReportingInterval", felixConf.Spec.ReportingInterval).Debug("Global Felix value already assigned")
		}

		if felixConf.Spec.LogSeverityScreen == "" {
			felixConf.Spec.LogSeverityScreen = defaultLogSeverity
			updateNeeded = true
		} else {
			log.WithField("LogSeverityScreen", felixConf.Spec.LogSeverityScreen).Debug("Global Felix value already assigned")
		}

		if updateNeeded {
			_, err = c.FelixConfigurations().Update(ctx, felixConf, options.SetOptions{})
			if err != nil {
				if conflict, ok := err.(cerrors.ErrorResourceUpdateConflict); ok {
					log.Infof("Ignoring conflict when setting value %s", conflict.Identifier)
				} else {
					log.WithError(err).WithField("FelixConfig", felixConf).Errorf("Error updating Felix global config")
					return err
				}
			}
		}
	}

	// Configure Felix to allow traffic from the containers to the host (if
	// not otherwise firewalled by the host administrator or profiles).
	// This is important for container deployments, where it is common
	// for containers to speak to services running on the host (e.g. k8s
	// pods speaking to k8s api-server, and mesos tasks registering with agent
	// on startup).  Note: KDD does not yet support per-node felix config.
	if cfg.Spec.DatastoreType != apiconfig.Kubernetes {
		felixNodeCfg, err := c.FelixConfigurations().Get(ctx, fmt.Sprintf("%s%s", felixNodeConfigNamePrefix, node.Name), options.GetOptions{})
		if err != nil {
			// Create the default config if it doesn't already exist.
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
				newFelixNodeCfg := api.NewFelixConfiguration()
				newFelixNodeCfg.Name = fmt.Sprintf("%s%s", felixNodeConfigNamePrefix, node.Name)
				newFelixNodeCfg.Spec.DefaultEndpointToHostAction = "Return"
				_, err = c.FelixConfigurations().Create(ctx, newFelixNodeCfg, options.SetOptions{})
				if err != nil {
					if exists, ok := err.(cerrors.ErrorResourceAlreadyExists); ok {
						log.Infof("Ignoring resource exists error when setting value %s", exists.Identifier)
					} else {
						log.WithError(err).WithField("FelixConfig", newFelixNodeCfg).Errorf("Error creating Felix node config")
						return err
					}
				}
			} else {
				log.WithError(err).WithField("FelixConfig", felixNodeConfigNamePrefix).Errorf("Error getting Felix node config")
				return err
			}
		} else {
			if felixNodeCfg.Spec.DefaultEndpointToHostAction == "" {
				felixNodeCfg.Spec.DefaultEndpointToHostAction = "Return"
				_, err = c.FelixConfigurations().Update(ctx, felixNodeCfg, options.SetOptions{})
				if err != nil {
					if conflict, ok := err.(cerrors.ErrorResourceUpdateConflict); ok {
						log.Infof("Ignoring conflict when setting value %s", conflict.Identifier)
					} else {
						log.WithError(err).WithField("FelixConfig", felixNodeCfg).Errorf("Error updating Felix node config")
						return err
					}
				}
			} else {
				log.WithField("DefaultEndpointToHostAction", felixNodeCfg.Spec.DefaultEndpointToHostAction).Debug("Host Felix value already assigned")
			}
		}
	}

	if err := ensureDefaultBGPConfigExists(ctx, c); err != nil {
		return err
	}

	return ensureDefaultIPAMConfigExists(ctx, c)
}

func ensureDefaultBGPConfigExists(ctx context.Context, c client.Interface) error {
	_, err := c.BGPConfigurations().Get(ctx, globalBGPConfigName, options.GetOptions{})
	if err == nil {
		log.Debug("Default BGPConfig exists.")
		return nil
	}

	_, ok := err.(cerrors.ErrorResourceDoesNotExist)
	if !ok {
		log.WithError(err).WithField("BGPConfig", globalBGPConfigName).Errorf("Error getting global BGPConfig.")
		return err
	}

	newBGPConf := api.NewBGPConfiguration()
	newBGPConf.Name = globalBGPConfigName
	_, err = c.BGPConfigurations().Create(ctx, newBGPConf, options.SetOptions{})
	if err != nil {
		if conflict, exists := err.(cerrors.ErrorResourceAlreadyExists); exists {
			log.Infof("Ignoring conflict when setting value %s", conflict.Identifier)
		} else {
			log.WithError(err).WithField("BGPConfig", newBGPConf).Errorf("Error creating default BGPConfiguration.")
			return err
		}
	}
	return nil
}

func ensureDefaultIPAMConfigExists(ctx context.Context, c client.Interface) error {
	_, err := c.IPAMConfiguration().Get(ctx, globalIPAMConfigName, options.GetOptions{})
	if err == nil {
		log.Debug("Default IPAMConfiguration exists.")
		return nil
	}

	_, ok := err.(cerrors.ErrorResourceDoesNotExist)
	if !ok {
		log.WithError(err).WithField("IPAMConfiguration", globalIPAMConfigName).Errorf("Error getting default IPAMConfiguration.")
		return err
	}

	// The meaningful IPAM defaults are not the zero value, so set them
	// explicitly. The kubebuilder defaults only apply through the apiserver
	// admission path, not on a direct client Create.
	newIPAMConf := api.NewIPAMConfiguration()
	newIPAMConf.Name = globalIPAMConfigName
	newIPAMConf.Spec.AutoAllocateBlocks = true
	newIPAMConf.Spec.MaxBlocksPerHost = 0
	newIPAMConf.Spec.KubeVirtVMAddressPersistence = ptr.To(api.VMAddressPersistenceEnabled)

	// Leave StrictAffinity disabled, matching the previous default. Windows
	// nodes require it enabled, but it's a single global setting and Windows
	// clusters are usually mixed with Linux, so we can't pick the right value
	// from one node at startup without racing the others. Windows clusters
	// enable it explicitly via "calicoctl ipam configure", and GetIPAMConfig
	// enforces it for Windows nodes.
	newIPAMConf.Spec.StrictAffinity = false
	_, err = c.IPAMConfiguration().Create(ctx, newIPAMConf, options.SetOptions{})
	if err != nil {
		if conflict, exists := err.(cerrors.ErrorResourceAlreadyExists); exists {
			log.Infof("Ignoring conflict when setting value %s", conflict.Identifier)
		} else {
			log.WithError(err).WithField("IPAMConfiguration", newIPAMConf).Errorf("Error creating default IPAMConfiguration.")
			return err
		}
	}
	return nil
}

// extractKubeadmCIDRs looks through the config map and parses lines starting with 'podSubnet'.
func extractKubeadmCIDRs(kubeadmConfig *v1.ConfigMap) (string, string, error) {
	var v4, v6 string
	var line []string
	var err error

	if kubeadmConfig == nil {
		return "", "", fmt.Errorf("invalid config map")
	}

	// Look through the config map for lines starting with 'podSubnet', then assign the right variable
	// according to the IP family of the matching string.
	re := regexp.MustCompile(`podSubnet: (.*)`)

	for _, l := range kubeadmConfig.Data {
		if line = re.FindStringSubmatch(l); line != nil {
			break
		}
	}

	if len(line) != 0 {
		// IPv4 and IPv6 CIDRs will be separated by a comma in a dual stack setup.
		for cidr := range strings.SplitSeq(line[1], ",") {
			addr, _, err := net.ParseCIDR(cidr)
			if err != nil {
				break
			}
			if addr.To4() == nil {
				if len(v6) == 0 {
					v6 = cidr
				}
			} else {
				if len(v4) == 0 {
					v4 = cidr
				}
			}
			if len(v6) != 0 && len(v4) != 0 {
				break
			}
		}
	}

	return v4, v6, err
}
