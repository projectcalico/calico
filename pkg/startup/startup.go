// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	"github.com/projectcalico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/upgrade/migrator"
	"github.com/projectcalico/libcalico-go/lib/upgrade/migrator/clients"

	"github.com/projectcalico/node/pkg/calicoclient"
	"github.com/projectcalico/node/pkg/startup/autodetection"
)

const (
	DEFAULT_IPV4_POOL_CIDR              = "192.168.0.0/16"
	DEFAULT_IPV4_POOL_NAME              = "default-ipv4-ippool"
	DEFAULT_IPV6_POOL_NAME              = "default-ipv6-ippool"
	AUTODETECTION_METHOD_FIRST          = "first-found"
	AUTODETECTION_METHOD_CAN_REACH      = "can-reach="
	AUTODETECTION_METHOD_INTERFACE      = "interface="
	AUTODETECTION_METHOD_SKIP_INTERFACE = "skip-interface="
)

// Default interfaces to exclude for any logic following the first-found
// auto detect IP method
var DEFAULT_INTERFACES_TO_EXCLUDE []string = []string{
	"docker.*", "cbr.*", "dummy.*",
	"virbr.*", "lxcbr.*", "veth.*", "lo",
	"cali.*", "tunl.*", "flannel.*", "kube-ipvs.*",
}

// Version string, set during build.
var VERSION string

// For testing purposes we define an exit function that we can override.
var exitFunction = os.Exit

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
	configureLogging()

	// Determine the name for this node.
	nodeName := determineNodeName()

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
			terminate()
		}
	}

	// Query the current Node resources.  We update our node resource with
	// updated IP data and use the full list of nodes for validation.
	node := getNode(ctx, cli, nodeName)

	// If Calico is running in policy only mode we don't need to write
	// BGP related details to the Node.
	if os.Getenv("CALICO_NETWORKING_BACKEND") != "none" {
		// Configure and verify the node IP addresses and subnets.
		checkConflicts, err := configureIPsAndSubnets(node)
		if err != nil {
			clearv4 := os.Getenv("IP") == "autodetect"
			clearv6 := os.Getenv("IP6") == "autodetect"
			if node.ResourceVersion != "" {
				// If we're auto-detecting an IP on an existing node and hit an error, clear the previous
				// IP addresses from the node since they are no longer valid.
				clearNodeIPs(ctx, cli, node, clearv4, clearv6)
			}
			terminate()
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

				terminate()
			}
		}

		// Configure the node AS number.
		configureASNumber(node)
	}

	configureNodeRef(node)

	// Check expected filesystem
	ensureFilesystemAsExpected()

	// Apply the updated node resource.
	if _, err := CreateOrUpdate(ctx, cli, node); err != nil {
		log.WithError(err).Errorf("Unable to set node resource configuration")
		terminate()
	}

	// Configure IP Pool configuration.
	configureIPPools(ctx, cli)

	// Set default configuration required for the cluster.
	if err := ensureDefaultConfig(ctx, cfg, cli, node); err != nil {
		log.WithError(err).Errorf("Unable to set global default configuration")
		terminate()
	}

	// Write config files now that we are ready to start other components.
	writeNodeConfig(nodeName)

	// Tell the user what the name of the node is.
	log.Infof("Using node name: %s", nodeName)
}

// configureNodeRef will attempt to discover the cluster type it is running on, check to ensure we
// have not already set it on this Node, and set it if need be.
func configureNodeRef(node *api.Node) {
	orchestrator := "k8s"
	nodeRef := ""

	// Sort out what type of cluster we're running on.
	if nodeRef = os.Getenv("CALICO_K8S_NODE_REF"); nodeRef == "" {
		return
	}

	node.Spec.OrchRefs = []api.OrchRef{api.OrchRef{NodeName: nodeRef, Orchestrator: orchestrator}}
}

// CreateOrUpdate creates the Node if ResourceVersion is not specified,
// or Update if it's specified.
func CreateOrUpdate(ctx context.Context, client client.Interface, node *api.Node) (*api.Node, error) {
	if node.ResourceVersion != "" {
		return client.Nodes().Update(ctx, node, options.SetOptions{})
	}

	return client.Nodes().Create(ctx, node, options.SetOptions{})
}

func clearNodeIPs(ctx context.Context, client client.Interface, node *api.Node, clearv4, clearv6 bool) {
	if clearv4 {
		log.WithField("IP", node.Spec.BGP.IPv4Address).Info("Clearing out-of-date IPv4 address from this node")
		node.Spec.BGP.IPv4Address = ""
	}
	if clearv6 {
		log.WithField("IP", node.Spec.BGP.IPv6Address).Info("Clearing out-of-date IPv6 address from this node")
		node.Spec.BGP.IPv6Address = ""
	}

	// If the BGP spec is empty, then set it to nil.
	if node.Spec.BGP != nil && reflect.DeepEqual(*node.Spec.BGP, api.NodeBGPSpec{}) {
		node.Spec.BGP = nil
	}

	if clearv4 || clearv6 {
		_, err := client.Nodes().Update(ctx, node, options.SetOptions{})
		if err != nil {
			log.WithError(err).Warnf("Failed to clear node addresses")
		}
	}
}

func configureLogging() {
	// Log to stdout.  this prevents our logs from being interpreted as errors by, for example,
	// fluentd's default configuration.
	log.SetOutput(os.Stdout)

	// Set log formatting.
	log.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file and line number information.
	log.AddHook(&logutils.ContextHook{})

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

// determineNodeName is called to determine the node name to use for this instance
// of calico/node.
func determineNodeName() string {
	var nodeName string
	var err error

	// Determine the name of this node.  Precedence is:
	// -  NODENAME
	// -  Value stored in /var/lib/calico/nodename
	// -  HOSTNAME (lowercase)
	// -  os.Hostname (lowercase).
	// We use the names.Hostname which lowercases and trims the name.
	if nodeName = strings.TrimSpace(os.Getenv("NODENAME")); nodeName != "" {
		log.Infof("Using NODENAME environment for node name")
	} else if nodeName = nodenameFromFile(); nodeName != "" {
		log.Info("Using stored node name from /var/lib/calico/nodename")
	} else if nodeName = strings.ToLower(strings.TrimSpace(os.Getenv("HOSTNAME"))); nodeName != "" {
		log.Infof("Using HOSTNAME environment (lowercase) for node name")
	} else if nodeName, err = names.Hostname(); err != nil {
		log.WithError(err).Error("Unable to determine hostname")
		terminate()
	} else {
		log.Warn("Using auto-detected node name. It is recommended that an explicit value is supplied using " +
			"the NODENAME environment variable.")
	}
	log.Infof("Determined node name: %s", nodeName)

	return nodeName
}

// nodenameFromFile reads the /var/lib/calico/nodename file if it exists and
// returns the nodename within.
func nodenameFromFile() string {
	data, err := ioutil.ReadFile("/var/lib/calico/nodename")
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return empty string.
			log.Debug("File does not exist: /var/lib/calico/nodename")
			return ""
		}
		log.WithError(err).Error("Failed to read /var/lib/calico/nodename")
		terminate()
	}
	return string(data)
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
				log.Warn("Connection to the datastore is unauthorized")
				terminate()
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

// writeNodeConfig writes out the this node's configuration to disk for use by other components.
// Specifically, it creates:
// - /var/lib/calico/nodename - used to persist the determined node name to disk for future use.
func writeNodeConfig(nodeName string) {
	log.Debugf("Writing %s to /var/lib/calico/nodename", nodeName)
	if err := ioutil.WriteFile("/var/lib/calico/nodename", []byte(nodeName), 0644); err != nil {
		log.WithError(err).Error("Unable to write to /var/lib/calico/nodename")
		terminate()
	}
}

// getNode returns the current node configuration. If this node has not yet
// been created, it returns a blank node resource.
func getNode(ctx context.Context, client client.Interface, nodeName string) *api.Node {
	node, err := client.Nodes().Get(ctx, nodeName, options.GetOptions{})

	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			log.WithError(err).WithField("Name", nodeName).Info("Unable to query node configuration")
			log.Warn("Unable to access datastore to query node configuration")
			terminate()
		}

		log.WithField("Name", nodeName).Info("Building new node resource")
		node = api.NewNode()
		node.Name = nodeName
	}

	return node
}

// configureIPsAndSubnets updates the supplied node resource with IP and Subnet
// information to use for BGP.  This returns true if we detect a change in Node IP address.
func configureIPsAndSubnets(node *api.Node) (bool, error) {
	// If the node resource currently has no BGP configuration, add an empty
	// set of configuration as it makes the processing below easier, and we
	// must end up configuring some BGP fields before we complete.
	if node.Spec.BGP == nil {
		log.Info("Initialize BGP data")
		node.Spec.BGP = &api.NodeBGPSpec{}
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
		cidr := autoDetectCIDR(adm, 4)
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
	} else if ipv4Env != "none" {
		if ipv4Env != "" {
			node.Spec.BGP.IPv4Address = parseIPEnvironment("IP", ipv4Env, 4)
		}
		validateIP(node.Spec.BGP.IPv4Address)
	}

	ipv6Env := os.Getenv("IP6")
	if ipv6Env == "autodetect" {
		adm := os.Getenv("IP6_AUTODETECTION_METHOD")
		cidr := autoDetectCIDR(adm, 6)
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
	} else if ipv6Env != "none" {
		if ipv6Env != "" {
			node.Spec.BGP.IPv6Address = parseIPEnvironment("IP6", ipv6Env, 6)
		}
		validateIP(node.Spec.BGP.IPv6Address)
	}

	if ipv4Env == "none" && (ipv6Env == "" || ipv6Env == "none") {
		log.Warn("No IP Addresses configured, and autodetection is not enabled")
		terminate()
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
		log.Warn("Environment does not contain a valid IPv%d address: %s=%s", version, envName, envValue)
		terminate()
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
		terminate()
	}

	// Get a complete list of interfaces with their addresses and check if
	// the IP address can be found.
	ifaces, err := autodetection.GetInterfaces(nil, nil, ipAddr.Version())
	if err != nil {
		log.WithError(err).Error("Unable to query host interfaces")
		terminate()
	}
	if len(ifaces) == 0 {
		log.Info("No interfaces found for validating IP configuration")
	}

	for _, i := range ifaces {
		for _, c := range i.Cidrs {
			if ipAddr.Equal(c.IP) {
				log.Infof("IPv%d address %s discovered on interface %s", ipAddr.Version(), ipAddr.String(), i.Name)
				return
			}
		}
	}
	log.Warnf("Unable to confirm IPv%d address %s is assigned to this host", ipAddr.Version(), ipAddr)
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

// autoDetectCIDR auto-detects the IP and Network using the requested
// detection method.
func autoDetectCIDR(method string, version int) *cnet.IPNet {
	if method == "" || method == AUTODETECTION_METHOD_FIRST {
		// Autodetect the IP by enumerating all interfaces (excluding
		// known internal interfaces).
		return autoDetectCIDRFirstFound(version)
	} else if strings.HasPrefix(method, AUTODETECTION_METHOD_INTERFACE) {
		// Autodetect the IP from the specified interface.
		ifStr := strings.TrimPrefix(method, AUTODETECTION_METHOD_INTERFACE)
		// Regexes are passed in as a string separated by ","
		ifRegexes := regexp.MustCompile("\\s*,\\s*").Split(ifStr, -1)
		return autoDetectCIDRByInterface(ifRegexes, version)
	} else if strings.HasPrefix(method, AUTODETECTION_METHOD_CAN_REACH) {
		// Autodetect the IP by connecting a UDP socket to a supplied address.
		destStr := strings.TrimPrefix(method, AUTODETECTION_METHOD_CAN_REACH)
		return autoDetectCIDRByReach(destStr, version)
	} else if strings.HasPrefix(method, AUTODETECTION_METHOD_SKIP_INTERFACE) {
		// Autodetect the Ip by enumerating all interfaces (excluding
		// known internal interfaces and any interfaces whose name
		// matches the given regexes).
		ifStr := strings.TrimPrefix(method, AUTODETECTION_METHOD_SKIP_INTERFACE)
		// Regexes are passed in as a string separated by ","
		ifRegexes := regexp.MustCompile("\\s*,\\s*").Split(ifStr, -1)
		return autoDetectCIDRBySkipInterface(ifRegexes, version)
	}

	// The autodetection method is not recognised and is required.  Exit.
	log.Errorf("Invalid IP autodection method: %s", method)
	terminate()
	return nil
}

// autoDetectCIDRFirstFound auto-detects the first valid Network it finds across
// all interfaces (excluding common known internal interface names).
func autoDetectCIDRFirstFound(version int) *cnet.IPNet {
	incl := []string{}

	iface, cidr, err := autodetection.FilteredEnumeration(incl, DEFAULT_INTERFACES_TO_EXCLUDE, version)
	if err != nil {
		log.Warnf("Unable to auto-detect an IPv%d address: %s", version, err)
		return nil
	}

	log.Infof("Using autodetected IPv%d address on interface %s: %s", version, iface.Name, cidr.String())

	return cidr
}

// autoDetectCIDRByInterface auto-detects the first valid Network on the interfaces
// matching the supplied interface regex.
func autoDetectCIDRByInterface(ifaceRegexes []string, version int) *cnet.IPNet {
	iface, cidr, err := autodetection.FilteredEnumeration(ifaceRegexes, nil, version)
	if err != nil {
		log.Warnf("Unable to auto-detect an IPv%d address using interface regexes %v: %s", version, ifaceRegexes, err)
		return nil
	}

	log.Infof("Using autodetected IPv%d address %s on matching interface %s", version, cidr.String(), iface.Name)

	return cidr
}

// autoDetectCIDRByReach auto-detects the IP and Network by setting up a UDP
// connection to a "reach" address.
func autoDetectCIDRByReach(dest string, version int) *cnet.IPNet {
	if cidr, err := autodetection.ReachDestination(dest, version); err != nil {
		log.Warnf("Unable to auto-detect IPv%d address by connecting to %s: %s", version, dest, err)
		return nil
	} else {
		log.Infof("Using autodetected IPv%d address %s, detected by connecting to %s", version, cidr.String(), dest)
		return cidr
	}
}

// autoDetectCIDRBySkipInterface auto-detects the first valid Network on the interfaces
// matching the supplied interface regexes.
func autoDetectCIDRBySkipInterface(ifaceRegexes []string, version int) *cnet.IPNet {
	incl := []string{}
	excl := DEFAULT_INTERFACES_TO_EXCLUDE
	excl = append(excl, ifaceRegexes...)

	iface, cidr, err := autodetection.FilteredEnumeration(incl, excl, version)
	if err != nil {
		log.Warnf("Unable to auto-detect an IPv%d address while excluding %v: %s", version, ifaceRegexes, err)
		return nil
	}

	log.Infof("Using autodetected IPv%d address on interface %s: %s while skipping matching interfaces", version, iface.Name, cidr.String())
	return cidr
}

// configureASNumber configures the Node resource with the AS number specified
// in the environment, or is a no-op if not specified.
func configureASNumber(node *api.Node) {
	// Extract the AS number from the environment
	asStr := os.Getenv("AS")
	if asStr != "" {
		if asNum, err := numorstring.ASNumberFromString(asStr); err != nil {
			log.WithError(err).Errorf("The AS number specified in the environment (AS=%s) is not valid", asStr)
			terminate()
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

// configureIPPools ensures that default IP pools are created (unless explicitly
// requested otherwise).
func configureIPPools(ctx context.Context, client client.Interface) {
	// Read in environment variables for use here and later.
	ipv4Pool := os.Getenv("CALICO_IPV4POOL_CIDR")
	ipv6Pool := os.Getenv("CALICO_IPV6POOL_CIDR")

	if strings.ToLower(os.Getenv("NO_DEFAULT_POOLS")) == "true" {
		if len(ipv4Pool) > 0 || len(ipv6Pool) > 0 {
			log.Error("Invalid configuration with NO_DEFAULT_POOLS defined and CALICO_IPV4POOL_CIDR or CALICO_IPV6POOL_CIDR defined.")
			terminate()
		}

		log.Info("Skipping IP pool configuration")
		return
	}

	ipv4IpipModeEnvVar := strings.ToLower(os.Getenv("CALICO_IPV4POOL_IPIP"))

	// Get a list of all IP Pools
	poolList, err := client.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Error("Unable to fetch IP pool list")
		terminate()
		return // not really needed but allows testing to function
	}

	// Check for IPv4 and IPv6 pools.
	ipv4Present := false
	ipv6Present := false
	for _, p := range poolList.Items {
		ip, _, err := cnet.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			log.Warnf("Error parsing CIDR '%s'. Skipping the IPPool.", p.Spec.CIDR)
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
	}
	_, ipv4Cidr, err := cnet.ParseCIDR(ipv4Pool)
	if err != nil || ipv4Cidr.Version() != 4 {
		log.Errorf("Invalid CIDR specified in CALICO_IPV4POOL_CIDR '%s'", ipv4Pool)
		terminate()
		return // not really needed but allows testing to function
	}

	// If no IPv6 pool is specified, generate one.
	if ipv6Pool == "" {
		ipv6Pool, err = GenerateIPv6ULAPrefix()
		if err != nil {
			log.Errorf("Failed to generate an IPv6 default pool")
			terminate()
		}
	}
	_, ipv6Cidr, err := cnet.ParseCIDR(ipv6Pool)
	if err != nil || ipv6Cidr.Version() != 6 {
		log.Errorf("Invalid CIDR specified in CALICO_IPV6POOL_CIDR '%s'", ipv6Pool)
		terminate()
		return // not really needed but allows testing to function
	}

	// Ensure there are pools created for each IP version.
	if !ipv4Present {
		log.Debug("Create default IPv4 IP pool")
		outgoingNATEnabled := evaluateENVBool("CALICO_IPV4POOL_NAT_OUTGOING", true)
		createIPPool(ctx, client, ipv4Cidr, DEFAULT_IPV4_POOL_NAME, ipv4IpipModeEnvVar, outgoingNATEnabled)
	}
	if !ipv6Present && ipv6Supported() {
		log.Debug("Create default IPv6 IP pool")
		outgoingNATEnabled := evaluateENVBool("CALICO_IPV6POOL_NAT_OUTGOING", false)

		createIPPool(ctx, client, ipv6Cidr, DEFAULT_IPV6_POOL_NAME, string(api.IPIPModeNever), outgoingNATEnabled)
	}
}

// ipv6Supported returns true if IPv6 is supported on this platform.  This performs
// a check on the appropriate Felix parameter and if supported also performs a
// simplistic check of /proc/sys/net/ipv6 (since platforms that do not have IPv6
// compiled in will not have this entry).
func ipv6Supported() bool {
	// First check if Felix param is false
	IPv6isSupported := evaluateENVBool("FELIX_IPV6SUPPORT", true)
	if !IPv6isSupported {
		return false
	}

	// If supported, then also check /proc/sys/net/ipv6.
	_, err := os.Stat("/proc/sys/net/ipv6")
	supported := (err == nil)
	log.Infof("IPv6 supported on this platform: %v", supported)
	return supported
}

// createIPPool creates an IP pool using the specified CIDR.  This
// method is a no-op if the pool already exists.
func createIPPool(ctx context.Context, client client.Interface, cidr *cnet.IPNet, poolName, ipipModeName string, isNATOutgoingEnabled bool) {
	version := cidr.Version()
	var ipipMode api.IPIPMode

	switch strings.ToLower(ipipModeName) {
	case "", "off", "never":
		ipipMode = api.IPIPModeNever
	case "crosssubnet", "cross-subnet":
		ipipMode = api.IPIPModeCrossSubnet
	case "always":
		ipipMode = api.IPIPModeAlways
	default:
		log.Errorf("Unrecognized IPIP mode specified in CALICO_IPV4POOL_IPIP '%s'", ipipModeName)
		terminate()
	}

	pool := &api.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: poolName,
		},
		Spec: api.IPPoolSpec{
			CIDR:        cidr.String(),
			NATOutgoing: isNATOutgoingEnabled,
			IPIPMode:    ipipMode,
		},
	}

	log.Infof("Ensure default IPv%d pool is created. IPIP mode: %s", version, ipipModeName)

	// Create the pool.  There is a small chance that another node may
	// beat us to it, so handle the fact that the pool already exists.
	if _, err := client.IPPools().Create(ctx, pool, options.SetOptions{}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceAlreadyExists); !ok {
			log.WithError(err).Errorf("Failed to create default IPv%d IP pool: %s", version)
			terminate()
		}
	} else {
		log.Infof("Created default IPv%d pool (%s) with NAT outgoing %t. IPIP mode: %s",
			version, cidr, isNATOutgoingEnabled, ipipModeName)
	}
}

// checkConflictingNodes checks whether any other nodes have been configured
// with the same IP addresses.
func checkConflictingNodes(ctx context.Context, client client.Interface, node *api.Node) (v4conflict, v6conflict bool, retErr error) {
	// Get the full set of nodes.
	var nodes []api.Node
	if nodeList, err := client.Nodes().List(ctx, options.ListOptions{}); err != nil {
		log.WithError(err).Errorf("Unable to query node confguration")
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

// Checks that the filesystem is as expected and fix it if possible
func ensureFilesystemAsExpected() {
	// BIRD requires the /var/run/calico directory in order to provide status
	// information over the control socket, but other backends do not
	// need this check.
	if strings.ToLower(os.Getenv("CALICO_NETWORKING_BACKEND")) == "bird" {
		runDir := "/var/run/calico"
		// Check if directory already exists
		if _, err := os.Stat(runDir); err != nil {
			// Create the runDir
			if err = os.MkdirAll(runDir, os.ModeDir); err != nil {
				log.Errorf("Unable to create '%s'", runDir)
				terminate()
			}
			log.Warnf("Expected %s to be mounted into the container but it wasn't present. 'calicoctl node status' may provide incomplete status information", runDir)
		}
	}

	// Make sure the /var/lib/calico directory exists.
	libDir := "/var/lib/calico"
	// Check if directory already exists
	if _, err := os.Stat(libDir); err != nil {
		// Create the libDir
		if err = os.MkdirAll(libDir, os.ModeDir); err != nil {
			log.Errorf("Unable to create '%s'", libDir)
			terminate()
		}
		log.Warnf("Expected %s to be mounted into the container but it wasn't present. Node name may not be detected properly", libDir)
	}

	// Ensure the log directory exists but only if logging to file is enabled.
	if strings.ToLower(os.Getenv("CALICO_DISABLE_FILE_LOGGING")) != "true" {
		logDir := "/var/log/calico"
		// Check if directory already exists
		if _, err := os.Stat(logDir); err != nil {
			// Create the logDir
			if err = os.MkdirAll(logDir, os.ModeDir); err != nil {
				log.Errorf("Unable to create '%s'", logDir)
				terminate()
			}
			log.Warnf("Expected %s to be mounted into the container but it wasn't present. 'calicoctl node diags' will not be able to collect calico/node logs", logDir)
		}
	}

}

// ensureDefaultConfig ensures all of the required default settings are
// configured.
func ensureDefaultConfig(ctx context.Context, cfg *apiconfig.CalicoAPIConfig, c client.Interface, node *api.Node) error {
	// Ensure the ClusterInformation is populated.
	// Get the ClusterType from ENV var. This is set from the manifest.
	clusterType := os.Getenv("CLUSTER_TYPE")
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
			return errors.New(fmt.Sprintf("Migration failed: %v", err))
		}
		log.Infof("Migration successful")
	} else {
		log.Debugf("Migration is not needed")
	}

	return nil
}

// terminate prints a terminate message and exists with status 1.
func terminate() {
	log.Warn("Terminating")
	exitFunction(1)
}
