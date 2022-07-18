// Copyright (c) 2016,2021 Tigera, Inc. All rights reserved.
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
package startup

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/migrator"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/migrator/clients"

	"github.com/projectcalico/calico/node/pkg/calicoclient"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup/autodetection"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup/autodetection/ipv4"
	"github.com/projectcalico/calico/node/pkg/lifecycle/utils"
)

const (
	DEFAULT_IPV4_POOL_CIDR       = "192.168.0.0/16"
	DEFAULT_IPV4_POOL_BLOCK_SIZE = 26
	DEFAULT_IPV6_POOL_BLOCK_SIZE = 122
	DEFAULT_IPV4_POOL_NAME       = "default-ipv4-ippool"
	DEFAULT_IPV6_POOL_NAME       = "default-ipv6-ippool"

	DEFAULT_MONITOR_IP_POLL_INTERVAL = 60 * time.Second

	// KubeadmConfigConfigMap is defined in k8s.io/kubernetes, which we can't import due to versioning issues.
	KubeadmConfigConfigMap = "kubeadm-config"
	// Rancher clusters store their state in this config map in the kube-system namespace.
	RancherStateConfigMap = "full-cluster-state"

	OSTypeLinux   = "lin"
	OSTypeWindows = "win"
)

// Version string, set during build.
var VERSION string

var (
	// Default values, names for different configs.
	defaultLogSeverity        = "Info"
	globalFelixConfigName     = "default"
	felixNodeConfigNamePrefix = "node."
)

// This file contains the main startup processing for the calico/node.  This
// includes:
// -  Detecting IP address and Network to use for BGP
// -  Configuring the node resource with IP/AS information provided in the
//    environment, or autodetected.
// -  Creating default IP Pools for quick-start use
func Run() {
	// Check $CALICO_STARTUP_LOGLEVEL to capture early log statements
	ConfigureLogging()

	// Determine the name for this node.
	nodeName := utils.DetermineNodeName()
	log.Infof("Starting node %s with version %s", nodeName, VERSION)

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

	if cfg.Spec.DatastoreType == apiconfig.Kubernetes {
		if err := ensureKDDMigrated(cfg, cli); err != nil {
			log.WithError(err).Errorf("Unable to ensure datastore is migrated.")
			utils.Terminate()
		}
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
	if config, err := rest.InClusterConfig(); err == nil {
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
			} else if kerrors.IsUnauthorized(err) {
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
			} else if kerrors.IsUnauthorized(err) {
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

	configureAndCheckIPAddressSubnets(ctx, cli, node, k8sNode)

	// If Calico is running in policy only mode we don't need to write BGP related details to the Node.
	if os.Getenv("CALICO_NETWORKING_BACKEND") != "none" {
		// Configure the node AS number.
		configureASNumber(node)
	}

	// Populate a reference to the node based on orchestrator node identifiers.
	configureNodeRef(node)

	// Check expected filesystem
	ensureFilesystemAsExpected()

	// Apply the updated node resource.
	if _, err := CreateOrUpdate(ctx, cli, node); err != nil {
		log.WithError(err).Errorf("Unable to set node resource configuration")
		utils.Terminate()
	}

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

	// All done. Set NetworkUnavailable to false if using Calico for networking.
	// We do it late in the process to avoid node resource update conflict because setting
	// node condition will trigger node-controller updating node taints.
	if os.Getenv("CALICO_NETWORKING_BACKEND") != "none" {
		if clientset != nil {
			err := utils.SetNodeNetworkUnavailableCondition(*clientset, k8sNodeName, false, 30*time.Second)
			if err != nil {
				log.WithError(err).Error("Unable to set NetworkUnavailable to False")
			}
		}
	}

	// Remove shutdownTS file when everything is done.
	// This indicates Calico node started successfully.
	if err := utils.RemoveShutdownTimestampFile(); err != nil {
		log.WithError(err).Errorf("Unable to remove shutdown timestamp file")
		utils.Terminate()
	}
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

func configureAndCheckIPAddressSubnets(ctx context.Context, cli client.Interface, node *libapi.Node, k8sNode *v1.Node) bool {
	// Configure and verify the node IP addresses and subnets.
	checkConflicts, err := configureIPsAndSubnets(node, k8sNode, autodetection.GetInterfaces)
	if err != nil {
		// If this is auto-detection error, do a cleanup before returning
		clearv4 := os.Getenv("IP") == "autodetect"
		clearv6 := os.Getenv("IP6") == "autodetect"
		if node.ResourceVersion != "" {
			// If we're auto-detecting an IP on an existing node and hit an error, clear the previous
			// IP addresses from the node since they are no longer valid.
			clearNodeIPs(ctx, cli, node, clearv4, clearv6)
		}

		utils.Terminate()
	}

	if node.Spec.BGP.IPv4Address == "" && node.Spec.BGP.IPv6Address == "" {
		if os.Getenv("CALICO_NETWORKING_BACKEND") != "none" {
			log.Error("No IPv4 or IPv6 addresses configured or detected, required for Calico networking")
			// Unrecoverable error, terminate to restart.
			utils.Terminate()
		} else {
			log.Info("No IPv4 or IPv6 addresses configured or detected. Some features may not work properly.")
			// Bail here setting BGPSpec to nil (if empty) to pass validation.
			if reflect.DeepEqual(node.Spec.BGP, &libapi.NodeBGPSpec{}) {
				node.Spec.BGP = nil
			}
			return checkConflicts
		}
	}

	// If we report an IP change (v4 or v6) we should verify there are no
	// conflicts between Nodes.
	if checkConflicts && os.Getenv("DISABLE_NODE_IP_CHECK") != "true" {
		v4conflict, v6conflict, err := checkConflictingNodes(ctx, cli, node)
		if err != nil {
			// If we've auto-detected a new IP address for an existing node that now conflicts, clear the old IP address(es)
			// from the node in the datastore. This frees the address in case it needs to be used for another node.
			clearv4 := (os.Getenv("IP") == "autodetect") && v4conflict
			clearv6 := (os.Getenv("IP6") == "autodetect") && v6conflict
			if node.ResourceVersion != "" {
				clearNodeIPs(ctx, cli, node, clearv4, clearv6)
			}
			utils.Terminate()
		}
	}

	return checkConflicts
}

func MonitorIPAddressSubnets() {
	ctx := context.Background()
	_, cli := calicoclient.CreateClient()
	nodeName := utils.DetermineNodeName()
	node := getNode(ctx, cli, nodeName)

	pollInterval := getMonitorPollInterval()

	var clientset *kubernetes.Clientset
	var config *rest.Config
	var k8sNode *v1.Node
	var err error

	// Determine the Kubernetes node name. Default to the Calico node name unless an explicit
	// value is provided.
	k8sNodeName := nodeName
	if nodeRef := os.Getenv("CALICO_K8S_NODE_REF"); nodeRef != "" {
		k8sNodeName = nodeRef
	}
	if config, err = rest.InClusterConfig(); err == nil {
		// Create the k8s clientset.
		clientset, err = kubernetes.NewForConfig(config)
		if err != nil {
			log.WithError(err).Error("Failed to create clientset")
			return
		}

		k8sNode, err = clientset.CoreV1().Nodes().Get(ctx, k8sNodeName, metav1.GetOptions{})
		if err != nil {
			log.WithError(err).Error("Failed to read Node from datastore")
			return
		}
	}

	for {
		<-time.After(pollInterval)
		log.Debugf("Checking node IP address every %v", pollInterval)
		updated := configureAndCheckIPAddressSubnets(ctx, cli, node, k8sNode)
		if updated {
			// Apply the updated node resource.
			// we try updating the resource up to 3 times, in case of transient issues.
			for i := 0; i < 3; i++ {
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
func configureNodeRef(node *libapi.Node) {
	orchestrator := "k8s"
	nodeRef := ""

	// Sort out what type of cluster we're running on.
	if nodeRef = os.Getenv("CALICO_K8S_NODE_REF"); nodeRef == "" {
		return
	}

	node.Spec.OrchRefs = []libapi.OrchRef{{NodeName: nodeRef, Orchestrator: orchestrator}}
}

// CreateOrUpdate creates the Node if ResourceVersion is not specified,
// or Update if it's specified.
func CreateOrUpdate(ctx context.Context, client client.Interface, node *libapi.Node) (*libapi.Node, error) {
	if node.ResourceVersion != "" {
		return client.Nodes().Update(ctx, node, options.SetOptions{})
	}

	return client.Nodes().Create(ctx, node, options.SetOptions{})
}

func clearNodeIPs(ctx context.Context, client client.Interface, node *libapi.Node, clearv4, clearv6 bool) {
	if clearv4 {
		log.WithField("IP", node.Spec.BGP.IPv4Address).Info("Clearing out-of-date IPv4 address from this node")
		node.Spec.BGP.IPv4Address = ""
	}
	if clearv6 {
		log.WithField("IP", node.Spec.BGP.IPv6Address).Info("Clearing out-of-date IPv6 address from this node")
		node.Spec.BGP.IPv6Address = ""
	}

	// If the BGP spec is empty, then set it to nil.
	if node.Spec.BGP != nil && reflect.DeepEqual(*node.Spec.BGP, libapi.NodeBGPSpec{}) {
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
func getNode(ctx context.Context, client client.Interface, nodeName string) *libapi.Node {
	node, err := client.Nodes().Get(ctx, nodeName, options.GetOptions{})
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			log.WithError(err).WithField("Name", nodeName).Info("Unable to query node configuration")
			log.Warn("Unable to access datastore to query node configuration")
			utils.Terminate()
		}

		log.WithField("Name", nodeName).Info("Building new node resource")
		node = libapi.NewNode()
		node.Name = nodeName
	}

	return node
}

// configureIPsAndSubnets updates the supplied node resource with IP and Subnet
// information to use for BGP.  This returns true if we detect a change in Node IP address.
func configureIPsAndSubnets(node *libapi.Node, k8sNode *v1.Node, getInterfaces func([]string, []string, int) ([]autodetection.Interface, error)) (bool, error) {
	// If the node resource currently has no BGP configuration, add an empty
	// set of configuration as it makes the processing below easier, and we
	// must end up configuring some BGP fields before we complete.
	if node.Spec.BGP == nil {
		log.Info("Initialize BGP data")
		node.Spec.BGP = &libapi.NodeBGPSpec{}
	}

	oldIpv4 := node.Spec.BGP.IPv4Address
	oldIpv6 := node.Spec.BGP.IPv6Address

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
			return false, fmt.Errorf("Failed to autodetect an IPv4 address")
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
			return false, fmt.Errorf("Failed to autodetect an IPv6 address")
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

	// Detect if we've seen the IP address change, and flag that we need to check for conflicting Nodes
	if node.Spec.BGP.IPv4Address != oldIpv4 {
		log.Info("Node IPv4 changed, will check for conflicts")
		return true, nil
	}
	if node.Spec.BGP.IPv6Address != oldIpv6 {
		log.Info("Node IPv6 changed, will check for conflicts")
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
	ifaces, err := autodetection.GetInterfaces(nil, nil, ipAddr.Version())
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
	if version == 4 {
		if blockSize < 20 || blockSize > 32 {
			log.Errorf("Invalid blocksize %d for version %d", blockSize, version)
			utils.Terminate()
		}
	} else if version == 6 {
		if blockSize < 116 || blockSize > 128 {
			log.Errorf("Invalid blocksize %d for version %d", blockSize, version)
			utils.Terminate()
		}
	} else {
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
func configureASNumber(node *libapi.Node) {
	// Extract the AS number from the environment
	asStr := os.Getenv("AS")
	if asStr != "" {
		if asNum, err := numorstring.ASNumberFromString(asStr); err != nil {
			log.WithError(err).Errorf("The AS number specified in the environment (AS=%s) is not valid", asStr)
			utils.Terminate()
		} else {
			log.Infof("Using AS number specified in environment (AS=%s)", asNum)
			node.Spec.BGP.ASNumber = &asNum
		}
	} else {
		if node.Spec.BGP.ASNumber == nil {
			log.Info("No AS number configured on node resource, using global value")
		} else {
			log.Infof("Using AS number %s configured in node resource", node.Spec.BGP.ASNumber)
		}
	}
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

	// If CIDRs weren't specified through the environment variables, check if they're present in kubeadm's
	// config map.
	if (len(ipv4Pool) == 0 || len(ipv6Pool) == 0) && kubeadmConfig != nil {
		v4, v6, err := extractKubeadmCIDRs(kubeadmConfig)
		if err == nil {
			if len(ipv4Pool) == 0 {
				ipv4Pool = v4
				log.Infof("found v4=%s in the kubeadm config map", ipv4Pool)
			}
			if len(ipv6Pool) == 0 {
				ipv6Pool = v6
				log.Infof("found v6=%s in the kubeadm config map", ipv6Pool)
			}
		} else {
			log.WithError(err).Warn("Failed to extract CIDRs from kubeadm config.")
		}
	}

	ipv4IpipModeEnvVar := strings.ToLower(os.Getenv("CALICO_IPV4POOL_IPIP"))
	ipv4VXLANModeEnvVar := strings.ToLower(os.Getenv("CALICO_IPV4POOL_VXLAN"))
	ipv6VXLANModeEnvVar := strings.ToLower(os.Getenv("CALICO_IPV6POOL_VXLAN"))

	var (
		ipv4BlockSize int
		ipv6BlockSize int
	)
	ipv4BlockSizeEnvVar := os.Getenv("CALICO_IPV4POOL_BLOCK_SIZE")
	if ipv4BlockSizeEnvVar != "" {
		ipv4BlockSize = parseBlockSizeEnvironment(ipv4BlockSizeEnvVar)
	} else {
		ipv4BlockSize = DEFAULT_IPV4_POOL_BLOCK_SIZE
	}
	validateBlockSize(4, ipv4BlockSize)
	ipv6BlockSizeEnvVar := os.Getenv("CALICO_IPV6POOL_BLOCK_SIZE")
	if ipv6BlockSizeEnvVar != "" {
		ipv6BlockSize = parseBlockSizeEnvironment(ipv6BlockSizeEnvVar)
	} else {
		ipv6BlockSize = DEFAULT_IPV6_POOL_BLOCK_SIZE
	}
	validateBlockSize(6, ipv6BlockSize)
	ipv4NodeSelector := os.Getenv("CALICO_IPV4POOL_NODE_SELECTOR")
	validateNodeSelector(4, ipv4NodeSelector)
	ipv6NodeSelector := os.Getenv("CALICO_IPV6POOL_NODE_SELECTOR")
	validateNodeSelector(6, ipv6NodeSelector)

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

	// Read IPV4 CIDR from env if set and parse then check it for errors
	if ipv4Pool == "" {
		ipv4Pool = DEFAULT_IPV4_POOL_CIDR

		_, preferedNet, _ := net.ParseCIDR(DEFAULT_IPV4_POOL_CIDR)
		if selectedPool, err := ipv4.GetDefaultIPv4Pool(preferedNet); err == nil {
			ipv4Pool = selectedPool.String()
		}

		log.Infof("Selected default IP pool is '%s'", ipv4Pool)
	}
	_, ipv4Cidr, err := cnet.ParseCIDR(ipv4Pool)
	if err != nil || ipv4Cidr.Version() != 4 {
		log.Errorf("Invalid CIDR specified in CALICO_IPV4POOL_CIDR '%s'", ipv4Pool)
		utils.Terminate()
		return // not really needed but allows testing to function
	}

	// If no IPv6 pool is specified, generate one.
	if ipv6Pool == "" {
		ipv6Pool, err = GenerateIPv6ULAPrefix()
		if err != nil {
			log.Errorf("Failed to generate an IPv6 default pool")
			utils.Terminate()
		}
	}
	_, ipv6Cidr, err := cnet.ParseCIDR(ipv6Pool)
	if err != nil || ipv6Cidr.Version() != 6 {
		log.Errorf("Invalid CIDR specified in CALICO_IPV6POOL_CIDR '%s'", ipv6Pool)
		utils.Terminate()
		return // not really needed but allows testing to function
	}

	// Ensure there are pools created for each IP version.
	if !ipv4Present {
		log.Debug("Create default IPv4 IP pool")
		outgoingNATEnabled := evaluateENVBool("CALICO_IPV4POOL_NAT_OUTGOING", true)
		bgpExportDisabled := evaluateENVBool("CALICO_IPV4POOL_DISABLE_BGP_EXPORT", false)

		createIPPool(ctx, client, ipv4Cidr, DEFAULT_IPV4_POOL_NAME, ipv4IpipModeEnvVar, ipv4VXLANModeEnvVar, outgoingNATEnabled, ipv4BlockSize, ipv4NodeSelector, bgpExportDisabled)
	}
	if !ipv6Present && ipv6Supported() {
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

// checkConflictingNodes checks whether any other nodes have been configured
// with the same IP addresses.
func checkConflictingNodes(ctx context.Context, client client.Interface, node *libapi.Node) (v4conflict, v6conflict bool, retErr error) {
	// Get the full set of nodes.
	var nodes []libapi.Node
	if nodeList, err := client.Nodes().List(ctx, options.ListOptions{}); err != nil {
		log.WithError(err).Errorf("Unable to query node configuration")
		retErr = err
		return
	} else {
		nodes = nodeList.Items
	}

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

	for _, theirNode := range nodes {
		if theirNode.Spec.BGP == nil {
			// Skip nodes that don't have BGP configured.  We know
			// that this node does have BGP since we only perform
			// this check after configuring BGP.
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

		// If this is our node (based on the name), check if the IP
		// addresses have changed.  If so warn the user as it could be
		// an indication of multiple nodes using the same name.  This
		// is not an error condition as the IPs could actually change.
		if theirNode.Name == node.Name {
			if theirIPv4.IP != nil && ourIPv4.IP != nil && !theirIPv4.IP.Equal(ourIPv4.IP) {
				fields := log.Fields{"node": theirNode.Name, "original": theirIPv4.String(), "updated": ourIPv4.String()}
				log.WithFields(fields).Warnf("IPv4 address has changed. This could happen if there are multiple nodes with the same name.")
			}
			if theirIPv6.IP != nil && ourIPv6.IP != nil && !theirIPv6.IP.Equal(ourIPv6.IP) {
				fields := log.Fields{"node": theirNode.Name, "original": theirIPv6.String(), "updated": ourIPv6.String()}
				log.WithFields(fields).Warnf("IPv6 address has changed. This could happen if there are multiple nodes with the same name.")
			}
			continue
		}

		// Check that other nodes aren't using the same IP addresses.
		// This is an error condition.
		if theirIPv4.IP != nil && ourIPv4.IP != nil && theirIPv4.IP.Equal(ourIPv4.IP) {
			log.Warnf("Calico node '%s' is already using the IPv4 address %s.", theirNode.Name, ourIPv4.String())
			retErr = fmt.Errorf("IPv4 address conflict")
			v4conflict = true
		}

		if theirIPv6.IP != nil && ourIPv6.IP != nil && theirIPv6.IP.Equal(ourIPv6.IP) {
			log.Warnf("Calico node '%s' is already using the IPv6 address %s.", theirNode.Name, ourIPv6.String())
			retErr = fmt.Errorf("IPv6 address conflict")
			v6conflict = true
		}
	}
	return
}

// ensureDefaultConfig ensures all of the required default settings are
// configured.
func ensureDefaultConfig(ctx context.Context, cfg *apiconfig.CalicoAPIConfig, c client.Interface, node *libapi.Node, osType string, kubeadmConfig, rancherState *v1.ConfigMap) error {
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

	if err := c.EnsureInitialized(ctx, VERSION, clusterType); err != nil {
		return nil
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

	return nil
}

// ensureKDDMigrated ensures any data migration needed is done.
func ensureKDDMigrated(cfg *apiconfig.CalicoAPIConfig, cv3 client.Interface) error {
	cv1, err := clients.LoadKDDClientV1FromAPIConfigV3(cfg)
	if err != nil {
		return err
	}
	m := migrator.New(cv3, cv1, nil)
	yes, err := m.ShouldMigrate()
	if err != nil {
		return err
	} else if yes {
		log.Infof("Running migration")
		if _, err = m.Migrate(); err != nil {
			return fmt.Errorf("Migration failed: %v", err)
		}
		log.Infof("Migration successful")
	} else {
		log.Debugf("Migration is not needed")
	}

	return nil
}

// extractKubeadmCIDRs looks through the config map and parses lines starting with 'podSubnet'.
func extractKubeadmCIDRs(kubeadmConfig *v1.ConfigMap) (string, string, error) {
	var v4, v6 string
	var line []string
	var err error

	if kubeadmConfig == nil {
		return "", "", fmt.Errorf("Invalid config map.")
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
		for _, cidr := range strings.Split(line[1], ",") {
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
