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
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/calico/calico_node/calicoclient"
	"github.com/projectcalico/calico/calico_node/startup/autodetection"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/ipip"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

const (
	DEFAULT_IPV4_POOL_CIDR              = "192.168.0.0/16"
	DEFAULT_IPV6_POOL_CIDR              = "fd80:24e2:f998:72d6::/64"
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
	"cali.*", "tunl.*", "flannel.*",
}

// For testing purposes we define an exit function that we can override.
var exitFunction = os.Exit

// This file contains the main startup processing for the calico/node.  This
// includes:
// -  Detecting IP address and Network to use for BGP
// -  Configuring the node resource with IP/AS information provided in the
//    environment, or autodetected.
// -  Creating default IP Pools for quick-start use

func main() {
	// Check $CALICO_STARTUP_LOGLEVEL to capture early log statements
	configureLogging()

	// Determine the name for this node and ensure the environment is always
	// available in the startup env file that is sourced in rc.local.
	nodeName := determineNodeName()

	// Create the Calico API client.
	cfg, client := calicoclient.CreateClient()

	// An explicit value of true is required to wait for the datastore.
	if os.Getenv("WAIT_FOR_DATASTORE") == "true" {
		waitForConnection(client)
		log.Info("Datastore is ready")
	} else {
		message("Skipping datastore connection test")
	}

	// Query the current Node resources.  We update our node resource with
	// updated IP data and use the full list of nodes for validation.
	node := getNode(client, nodeName)

	// Configure and verify the node IP addresses and subnets.
	configureIPsAndSubnets(node)

	// Configure the node AS number.
	configureASNumber(node)

	// Check for conflicting node configuration
	checkConflictingNodes(client, node)

	// Check expected filesystem
	ensureFilesystemAsExpected()

	// Apply the updated node resource.
	if _, err := client.Nodes().Apply(node); err != nil {
		fatal("Unable to set node resource configuration: %s", err)
		terminate()
	}

	// Configure IP Pool configuration.
	configureIPPools(client)

	// Set other Felix config that is not yet in the node resource.  Skip for Kubernetes as
	// the keys do not yet exist
	if cfg.Spec.DatastoreType != api.Kubernetes {
		if err := ensureDefaultConfig(client, node); err != nil {
			fatal("Unable to set global default configuration: %s", err)
			terminate()
		}
	}

	// Write the startup.env file now that we are ready to start other
	// components.
	writeStartupEnv(nodeName, node.Spec.BGP.IPv4Address, node.Spec.BGP.IPv6Address)

	// Tell the user what the name of the node is.
	message("Using node name: %s", nodeName)
}

func configureLogging() {
	// Default to error logging
	logLevel := log.ErrorLevel

	rawLogLevel := os.Getenv("CALICO_STARTUP_LOGLEVEL")
	if rawLogLevel != "" {
		parsedLevel, err := log.ParseLevel(rawLogLevel)
		if err == nil {
			logLevel = parsedLevel
		} else {
			log.WithError(err).Error("Failed to parse log level, defaulting to error.")
		}
	}

	log.SetLevel(logLevel)
	log.Infof("Early log level set to %v", logLevel)
}

// determineNodeName is called to determine the node name to use for this instance
// of calico/node.
func determineNodeName() string {
	// Determine the name of this node.
	nodeName := os.Getenv("NODENAME")
	if nodeName == "" {
		// NODENAME not specified, check HOSTNAME (we maintain this for
		// backwards compatibility).
		log.Info("NODENAME environment not specified - check HOSTNAME")
		nodeName = os.Getenv("HOSTNAME")
	}
	if nodeName == "" {
		// The node name has not been specified.  We need to use the OS
		// hostname - but should warn the user that this is not a
		// recommended way to start the node container.
		var err error
		if nodeName, err = os.Hostname(); err != nil {
			log.Info("Unable to determine hostname - exiting")
			panic(err)
		}

		message("******************************************************************************")
		message("* WARNING                                                                    *")
		message("* Auto-detecting node name.  It is recommended that an explicit fixed value  *")
		message("* is supplied using the NODENAME environment variable.  Using a fixed value  *")
		message("* ensures that any changes to the compute host's hostname will not affect    *")
		message("* the Calico configuration when calico/node restarts.                        *")
		message("******************************************************************************")
	}
	return nodeName
}

// waitForConnection waits for the datastore to become accessible.
func waitForConnection(c *client.Client) {
	message("Checking datastore connection")
	for {
		// Query some arbitrary configuration to see if the connection
		// is working.  Getting a specific Node is a good option, even
		// if the Node does not exist.
		_, err := c.Nodes().Get(api.NodeMetadata{Name: "foo"})

		// We only care about a couple of error cases, all others would
		// suggest the datastore is accessible.
		if err != nil {
			switch err.(type) {
			case errors.ErrorConnectionUnauthorized:
				fatal("Connection to the datastore is unauthorized")
				terminate()
			case errors.ErrorDatastoreError:
				time.Sleep(1000 * time.Millisecond)
				continue
			}
		}

		// We've connected to the datastore - break out of the loop.
		break
	}
	message("Datastore connection verified")
}

// writeStartupEnv writes out the startup.env file to set environment variables
// that are required by confd/bird etc. but may not have been passed into the
// container.
func writeStartupEnv(nodeName string, ip, ip6 *net.IPNet) {
	text := "export NODENAME=" + nodeName + "\n"

	// TODO:  See https://github.com/projectcalico/calico-bgp-daemon/issues/18
	// The following entries are required for go-bgp.  Once updated to use
	// NODENAME and the node IP parameters, these entries can be removed.
	text += "export HOSTNAME=" + nodeName + "\n"
	if ip != nil {
		text += "export IP=" + ip.IP.String() + "\n"
	}
	if ip6 != nil {
		text += "export IP6=" + ip6.IP.String() + "\n"
	}

	// Write out the startup.env file to ensure required environments are
	// set (which they might not otherwise be).
	if err := ioutil.WriteFile("startup.env", []byte(text), 0666); err != nil {
		log.WithError(err).Info("Unable to write to startup.env")
		fatal("Unable to write to local filesystem")
		terminate()
	}
}

// getNode returns the current node configuration.  If this node has not yet
// been created, it returns a blank node resource.
func getNode(client *client.Client, nodeName string) *api.Node {
	meta := api.NodeMetadata{Name: nodeName}
	node, err := client.Nodes().Get(meta)

	if err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			log.WithError(err).WithField("Name", nodeName).Info("Unable to query node configuration")
			fatal("Unable to access datastore to query node configuration")
			terminate()
		}

		log.WithField("Name", nodeName).Info("Building new node resource")
		node = &api.Node{Metadata: api.NodeMetadata{Name: nodeName}}
	}

	return node
}

// configureIPsAndSubnets updates the supplied node resource with IP and Subnet
// information to use for BGP.
func configureIPsAndSubnets(node *api.Node) {
	// If the node resource currently has no BGP configuration, add an empty
	// set of configuration as it makes the processing below easier, and we
	// must end up configuring some BGP fields before we complete.
	if node.Spec.BGP == nil {
		log.Info("Initialise BGP data")
		node.Spec.BGP = &api.NodeBGPSpec{}
	}

	// Determine the autodetection type for IPv4 and IPv6.  Note that we
	// only autodetect IPv4 when it has not been specified.  IPv6 must be
	// explicitly requested using the "autodetect" value.
	//
	// If we aren't auto-detecting then we need to validate the configured
	// value and possibly fix up missing subnet configuration.
	ipv4Env := os.Getenv("IP")
	if ipv4Env == "autodetect" || (ipv4Env == "" && node.Spec.BGP.IPv4Address == nil) {
		adm := os.Getenv("IP_AUTODETECTION_METHOD")
		cidr := autoDetectCIDR(adm, 4)
		if cidr != nil {
			// We autodetected an IPv4 address so update the value in the node.
			node.Spec.BGP.IPv4Address = cidr
		} else if node.Spec.BGP.IPv4Address == nil {
			// No IPv4 address is configured, but we always require one, so exit.
			fatal("Couldn't autodetect a management IPv4 address:")
			message("  -  provide an IPv4 address by configuring one in the node resource, or")
			message("  -  provide an IPv4 address using the IP environment, or")
			message("  -  if auto-detecting, use a different autodetection method.")
			terminate()
		} else {
			// No IPv4 autodetected, but a previous one was configured.
			// Tell the user we are leaving the value unchanged.  We
			// will validate that the IP matches one on the interface.
			warning("Autodetection of IPv4 address failed, keeping existing value: %s", node.Spec.BGP.IPv4Address.String())
			validateIP(node.Spec.BGP.IPv4Address)
		}
	} else {
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
			node.Spec.BGP.IPv6Address = cidr
		} else if node.Spec.BGP.IPv6Address == nil {
			// No IPv6 address is configured, but we have requested one, so exit.
			fatal("Couldn't autodetect a management IPv6 address:")
			message("  -  provide an IPv6 address by configuring one in the node resource, or")
			message("  -  provide an IPv6 address using the IP6 environment, or")
			message("  -  use a different autodetection method, or")
			message("  -  don't request autodetection of an IPv6 address.")
			terminate()
		} else {
			// No IPv6 autodetected, but a previous one was configured.
			// Tell the user we are leaving the value unchanged.  We
			// will validate that the IP matches one on the interface.
			warning("Autodetection of IPv6 address failed, keeping existing value: %s", node.Spec.BGP.IPv6Address.String())
			validateIP(node.Spec.BGP.IPv4Address)
		}
	} else {
		if ipv6Env != "" {
			node.Spec.BGP.IPv6Address = parseIPEnvironment("IP6", ipv6Env, 6)
		}
		validateIP(node.Spec.BGP.IPv6Address)
	}

}

// fetchAndValidateIPAndNetwork fetches and validates the IP configuration from
// either the environment variables or from the values already configured in the
// node.
func parseIPEnvironment(envName, envValue string, version int) *net.IPNet {
	// To parse the environment (which could be an IP or a CIDR), convert
	// to a JSON string and use the UnmarshalJSON method on the IPNet
	// struct to parse the value.
	ip := &net.IPNet{}
	err := ip.UnmarshalJSON([]byte("\"" + envValue + "\""))
	if err != nil || ip.Version() != version {
		fatal("Environment does not contain a valid IPv%d address: %s=%s", version, envName, envValue)
		terminate()
	}
	message("Using IPv%d address from environment: %s=%s", ip.Version(), envName, envValue)

	return ip
}

// validateIP checks that the IP address is actually on one of the host
// interfaces and warns if not.
func validateIP(ipn *net.IPNet) {
	// No validation required if no IP address is specified.
	if ipn == nil {
		return
	}

	// Pull out the IP as a net.IP (it has useful string and version methods).
	ip := net.IP{ipn.IP}

	// Get a complete list of interfaces with their addresses and check if
	// the IP address can be found.
	ifaces, err := autodetection.GetInterfaces(nil, nil, ip.Version())
	if err != nil {
		fatal("Unable to query host interfaces: %s", err)
		terminate()
	}
	if len(ifaces) == 0 {
		message("No interfaces found for validating IP configuration")
	}

	for _, i := range ifaces {
		for _, c := range i.Cidrs {
			if ip.Equal(c.IP) {
				message("IPv%d address %s discovered on interface %s", ip.Version(), ip.String(), i.Name)
				return
			}
		}
	}
	warning("Unable to confirm IPv%d address %s is assigned to this host", ip.Version(), ip)
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
func autoDetectCIDR(method string, version int) *net.IPNet {
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
	fatal("Invalid IP autodection method: %s", method)
	terminate()
	return nil
}

// autoDetectCIDRFirstFound auto-detects the first valid Network it finds across
// all interfaces (excluding common known internal interface names).
func autoDetectCIDRFirstFound(version int) *net.IPNet {
	incl := []string{}

	iface, cidr, err := autodetection.FilteredEnumeration(incl, DEFAULT_INTERFACES_TO_EXCLUDE, version)
	if err != nil {
		warning("Unable to auto-detect an IPv%d address: %s", version, err)
		return nil
	}

	message("Using autodetected IPv%d address on interface %s: %s", version, iface.Name, cidr.String())

	return cidr
}

// autoDetectCIDRByInterface auto-detects the first valid Network on the interfaces
// matching the supplied interface regex.
func autoDetectCIDRByInterface(ifaceRegexes []string, version int) *net.IPNet {
	iface, cidr, err := autodetection.FilteredEnumeration(ifaceRegexes, nil, version)
	if err != nil {
		warning("Unable to auto-detect an IPv%d address using interface regexes %v: %s", version, ifaceRegexes, err)
		return nil
	}

	message("Using autodetected IPv%d address %s on matching interface %s", version, cidr.String(), iface.Name)

	return cidr
}

// autoDetectCIDRByReach auto-detects the IP and Network by setting up a UDP
// connection to a "reach" address.
func autoDetectCIDRByReach(dest string, version int) *net.IPNet {
	if cidr, err := autodetection.ReachDestination(dest, version); err != nil {
		warning("Unable to auto-detect IPv%d address by connecting to %s: %s", version, dest, err)
		return nil
	} else {
		message("Using autodetected IPv%d address %s, detected by connecting to %s", version, cidr.String(), dest)
		return cidr
	}
}

// autoDetectCIDRBySkipInterface auto-detects the first valid Network on the interfaces
// matching the supplied interface regexes.
func autoDetectCIDRBySkipInterface(ifaceRegexes []string, version int) *net.IPNet {
	incl := []string{}
	excl := DEFAULT_INTERFACES_TO_EXCLUDE
	excl = append(excl, ifaceRegexes...)

	iface, cidr, err := autodetection.FilteredEnumeration(incl, excl, version)
	if err != nil {
		warning("Unable to auto-detect an IPv%d address while excluding %v: %s", version, ifaceRegexes, err)
		return nil
	}

	message("Using autodetected IPv%d address on interface %s: %s while skipping matching interfaces", version, iface.Name, cidr.String())

	return cidr
}

// configureASNumber configures the Node resource with the AS number specified
// in the environment, or is a no-op if not specified.
func configureASNumber(node *api.Node) {
	// Extract the AS number from the environment
	asStr := os.Getenv("AS")
	if asStr != "" {
		if asNum, err := numorstring.ASNumberFromString(asStr); err != nil {
			fatal("The AS number specified in the environment (AS=%s) is not valid: %s", asStr, err)
			terminate()
		} else {
			message("Using AS number specified in environment (AS=%s)", asNum)
			node.Spec.BGP.ASNumber = &asNum
		}
	} else {
		if node.Spec.BGP.ASNumber == nil {
			message("No AS number configured on node resource, using global value")
		} else {
			message("Using AS number %s configured in node resource", node.Spec.BGP.ASNumber)
		}
	}
}

// configureIPPools ensures that default IP pools are created (unless explicitly
// requested otherwise).
func configureIPPools(client *client.Client) {
	// Read in environment variables for use here and later.
	ipv4Pool := os.Getenv("CALICO_IPV4POOL_CIDR")
	ipv6Pool := os.Getenv("CALICO_IPV6POOL_CIDR")

	if strings.ToLower(os.Getenv("NO_DEFAULT_POOLS")) == "true" {
		if len(ipv4Pool) > 0 || len(ipv6Pool) > 0 {
			fatal("Invalid configuration with NO_DEFAULT_POOLS defined and CALICO_IPV4POOL_CIDR or CALICO_IPV6POOL_CIDR defined.")
			terminate()
		}

		log.Info("Skipping IP pool configuration")
		return
	}

	ipv4IpipModeEnvVar := strings.ToLower(os.Getenv("CALICO_IPV4POOL_IPIP"))

	// Get a list of all IP Pools
	poolList, err := client.IPPools().List(api.IPPoolMetadata{})
	if err != nil {
		fatal("Unable to fetch IP pool list: %s", err)
		terminate()
		return // not really needed but allows testing to function
	}

	// Check for IPv4 and IPv6 pools.
	ipv4Present := false
	ipv6Present := false
	for _, p := range poolList.Items {
		version := p.Metadata.CIDR.Version()
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
	_, ipv4Cidr, err := net.ParseCIDR(ipv4Pool)
	if err != nil || ipv4Cidr.Version() != 4 {
		fatal("Invalid CIDR specified in CALICO_IPV4POOL_CIDR '%s'", ipv4Pool)
		terminate()
		return // not really needed but allows testing to function
	}

	// Read IPV6 CIDR from env if set and parse then check it for errors
	if ipv6Pool == "" {
		ipv6Pool = DEFAULT_IPV6_POOL_CIDR
	}
	_, ipv6Cidr, err := net.ParseCIDR(ipv6Pool)
	if err != nil || ipv6Cidr.Version() != 6 {
		fatal("Invalid CIDR specified in CALICO_IPV6POOL_CIDR '%s'", ipv6Pool)
		terminate()
		return // not really needed but allows testing to function
	}

	// Ensure there are pools created for each IP version.
	if !ipv4Present {
		log.Debug("Create default IPv4 IP pool")
		outgoingNATEnabled := evaluateENVBool("CALICO_IPV4POOL_NAT_OUTGOING", true)
		createIPPool(client, ipv4Cidr, ipv4IpipModeEnvVar, outgoingNATEnabled)
	}
	if !ipv6Present && ipv6Supported() {
		log.Debug("Create default IPv6 IP pool")
		outgoingNATEnabled := evaluateENVBool("CALICO_IPV6POOL_NAT_OUTGOING", false)

		createIPPool(client, ipv6Cidr, string(ipip.Undefined), outgoingNATEnabled)
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
func createIPPool(client *client.Client, cidr *net.IPNet, ipipModeName string, isNATOutgoingEnabled bool) {
	version := cidr.Version()
	ipipMode := ipip.Mode(ipipModeName)

	// off is not an actual valid value so switch it to an empty string
	if ipipModeName == "off" {
		ipipMode = ipip.Undefined
	}

	pool := &api.IPPool{
		Metadata: api.IPPoolMetadata{
			CIDR: *cidr,
		},
		Spec: api.IPPoolSpec{
			NATOutgoing: isNATOutgoingEnabled,
			IPIP: &api.IPIPConfiguration{
				Enabled: ipipMode != ipip.Undefined,
				Mode:    ipipMode,
			},
		},
	}

	// Use off when logging for disabled instead of blank
	if ipipMode == ipip.Undefined {
		ipipModeName = "off"
	}

	log.Infof("Ensure default IPv%d pool is created. IPIP mode: %s", version, ipipModeName)

	// Create the pool.  There is a small chance that another node may
	// beat us to it, so handle the fact that the pool already exists.
	if _, err := client.IPPools().Create(pool); err != nil {
		if _, ok := err.(errors.ErrorResourceAlreadyExists); !ok {
			fatal("Failed to create default IPv%d IP pool: %s", version, err)
			terminate()
		}
	} else {
		message("Created default IPv%d pool (%s) with NAT outgoing %t. IPIP mode: %s",
			version, cidr, isNATOutgoingEnabled, ipipModeName)
	}
}

// checkConflictingNodes checks whether any other nodes have been configured
// with the same IP addresses.
func checkConflictingNodes(client *client.Client, node *api.Node) {
	// Get the full set of nodes.
	var nodes []api.Node
	if nodeList, err := client.Nodes().List(api.NodeMetadata{}); err != nil {
		fatal("Unable to query node confguration: %s", err)
		terminate()
	} else {
		nodes = nodeList.Items
	}

	ourIPv4 := node.Spec.BGP.IPv4Address
	ourIPv6 := node.Spec.BGP.IPv6Address
	errored := false
	for _, theirNode := range nodes {
		if theirNode.Spec.BGP == nil {
			// Skip nodes that don't have BGP configured.  We know
			// that this node does have BGP since we only perform
			// this check after configuring BGP.
			continue
		}
		theirIPv4 := theirNode.Spec.BGP.IPv4Address
		theirIPv6 := theirNode.Spec.BGP.IPv6Address

		// If this is our node (based on the name), check if the IP
		// addresses have changed.  If so warn the user as it could be
		// an indication of multiple nodes using the same name.  This
		// is not an error condition as the IPs could actually change.
		if theirNode.Metadata.Name == node.Metadata.Name {
			if theirIPv4 != nil && ourIPv4 != nil && !theirIPv4.IP.Equal(ourIPv4.IP) {
				warning("Calico node '%s' IPv4 address has changed:",
					theirNode.Metadata.Name)
				message(" -  This could happen if multiple nodes are configured with the same name")
				message(" -  Original IP: %s", theirIPv4.IP)
				message(" -  Updated IP: %s", ourIPv4.IP)
			}
			if theirIPv6 != nil && ourIPv6 != nil && !theirIPv6.IP.Equal(ourIPv6.IP) {
				warning("Calico node '%s' IPv6 address has changed:",
					theirNode.Metadata.Name)
				message(" -  This could happen if multiple nodes are configured with the same name")
				message(" -  Original IP: %s", theirIPv6.IP)
				message(" -  Updated IP: %s", ourIPv6.IP)
			}
			continue
		}

		// Check that other nodes aren't using the same IP addresses.
		// This is an error condition.
		if theirIPv4 != nil && ourIPv4 != nil && theirIPv4.IP.Equal(ourIPv4.IP) {
			message("Calico node '%s' is already using the IPv4 address %s:",
				theirNode.Metadata.Name, ourIPv4.IP)
			message(" -  Check the node configuration to remove the IP address conflict")
			errored = true
		}
		if theirIPv6 != nil && ourIPv6 != nil && theirIPv6.IP.Equal(ourIPv6.IP) {
			message("Calico node '%s' is already using the IPv6 address %s:",
				theirNode.Metadata.Name, ourIPv6.IP)
			message(" -  Check the node configuration to remove the IP address conflict")
			errored = true
		}
	}

	if errored {
		terminate()
	}
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
				fatal("Unable to create '%s'", runDir)
				terminate()
			}
			warning("%s was not mounted, 'calicoctl node status' may provide incomplete status information", runDir)
		}
	}

	// Ensure the log directory exists but only if logging to file is enabled.
	if strings.ToLower(os.Getenv("CALICO_DISABLE_FILE_LOGGING")) != "true" {
		logDir := "/var/log/calico"
		// Check if directory already exists
		if _, err := os.Stat(logDir); err != nil {
			// Create the logDir
			if err = os.MkdirAll(logDir, os.ModeDir); err != nil {
				fatal("Unable to create '%s'", logDir)
				terminate()
			}
			warning("%s was not mounted, 'calicoctl node diags' will not be able to collect logs", logDir)
		}
	}

}

// ensureDefaultConfig ensures all of the required default settings are
// configured.
func ensureDefaultConfig(c *client.Client, node *api.Node) error {
	// By default we set the global reporting interval to 0 - this is
	// different from the defaults defined in Felix.
	//
	// Logging to file is disabled in the felix.cfg config file.  This
	// should always be disabled for calico/node.  By default we log to
	// screen - set the default logging value that we desire.
	if err := ensureGlobalFelixConfig(c, "ReportingIntervalSecs", "0"); err != nil {
		return err
	} else if err = ensureGlobalFelixConfig(c, "LogSeverityScreen", client.GlobalDefaultLogLevel); err != nil {
		return err
	}

	// Configure Felix to allow traffic from the containers to the host (if
	// not otherwise firewalled by the host administrator or profiles).
	// This is important for container deployments, where it is common
	// for containers to speak to services running on the host (e.g. k8s
	// pods speaking to k8s api-server, and mesos tasks registering with agent
	// on startup).
	if err := ensureFelixConfig(c, node.Metadata.Name, "DefaultEndpointToHostAction", "RETURN"); err != nil {
		return err
	}

	// Set the default values for some of the global BGP config values and
	// per-node directory structure.
	// These are required by both confd and the GoBGP daemon.  Some of this
	// can only be done directly by the backend (since it requires access to
	// datastore features not exposed in the main API).
	//
	// TODO: This is only required for the current BIRD and GoBGP integrations,
	//       but should be removed once we switch over to a better watcher interface.
	if err := ensureGlobalBGPConfig(c, "node_mesh", fmt.Sprintf("{\"enabled\": %v}", client.GlobalDefaultNodeToNodeMesh)); err != nil {
		return err
	} else if err := ensureGlobalBGPConfig(c, "as_num", strconv.Itoa(client.GlobalDefaultASNumber)); err != nil {
		return err
	} else if err = ensureGlobalBGPConfig(c, "loglevel", client.GlobalDefaultLogLevel); err != nil {
		return err
	} else if err = c.Backend.EnsureCalicoNodeInitialized(node.Metadata.Name); err != nil {
		return err
	}
	return nil
}

// ensureGlobalFelixConfig ensures that the supplied global felix config value
// is initialized, and if not initialize it with the supplied default.
func ensureGlobalFelixConfig(c *client.Client, key, def string) error {
	if val, assigned, err := c.Config().GetFelixConfig(key, ""); err != nil {
		return err
	} else if !assigned {
		return c.Config().SetFelixConfig(key, "", def)
	} else {
		log.WithField(key, val).Debug("Global Felix value already assigned")
		return nil
	}
}

// ensureFelixConfig ensures that the supplied felix config value
// is initialized, and if not initialize it with the supplied default.
func ensureFelixConfig(c *client.Client, host, key, def string) error {
	if val, assigned, err := c.Config().GetFelixConfig(key, host); err != nil {
		return err
	} else if !assigned {
		return c.Config().SetFelixConfig(key, host, def)
	} else {
		log.WithField(key, val).Debug("Host Felix value already assigned")
		return nil
	}
}

// ensureGlobalBGPConfig ensures that the supplied global BGP config value
// is initialized, and if not initialize it with the supplied default.
func ensureGlobalBGPConfig(c *client.Client, key, def string) error {
	if val, assigned, err := c.Config().GetBGPConfig(key, ""); err != nil {
		return err
	} else if !assigned {
		return c.Config().SetBGPConfig(key, "", def)
	} else {
		log.WithField(key, val).Debug("Global BGP value already assigned")
		return nil
	}
}

// message prints a message to screen and to log.  A newline terminator is
// not required in the format string.
func message(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

// warning prints a warning to screen and to log.  A newline terminator is
// not required in the format string.
func warning(format string, args ...interface{}) {
	fmt.Printf("WARNING: "+format+"\n", args...)
}

// fatal prints a fatal message to screen and to log.  A newline terminator is
// not required in the format string.
func fatal(format string, args ...interface{}) {
	fmt.Printf("ERROR: "+format+"\n", args...)
}

// terminate prints a terminate message and exists with status 1.
func terminate() {
	message("Terminating")
	exitFunction(1)
}
