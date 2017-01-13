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
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/calicoctl/calico_node/calicoclient"
	"github.com/projectcalico/calicoctl/calico_node/startup/autodetection"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

const (
	DEFAULT_IPV4_POOL_CIDR = "192.168.0.0/16"
	DEFAULT_IPV6_POOL_CIDR = "fd80:24e2:f998:72d6::/64"
)

// For testing purposes we define an exit function that we can override.
var exitFunction = os.Exit

// This file contains the main startup processing for the calico/node.  This
// includes:
// -  Detecting IP address and Network to use for BGP
// -  Configuring the node resource with IP/AS information provided in the
//    environment, or autodetected.
// -  Creating default IP Pools for quick-start use
// -  TODO:  Configuring IPIP tunnel with an IP address from an IP pool
// TODO: Different auto-detection methods

func main() {
	var err error

	// Determine the name for this node.
	nodeName := determineNodeName()

	// Create the Calico API client.
	cfg, client := calicoclient.CreateClient()

	// An explicit value of true is required to wait for the datastore.
	if os.Getenv("WAIT_FOR_DATASTORE") == "true" {
		waitForConnection(client)
	} else {
		message("Skipping datastore connection test")
	}

	// If this is a Kubernetes backed datastore then just make sure the
	// datastore is initialized and then exit.  We don't need to explicitly
	// initialize the datastore for non-Kubernetes because the node resource
	// management will do that for us.
	if cfg.Spec.DatastoreType == api.Kubernetes {
		message("Calico is using a Kubernetes datastore")
		err = client.EnsureInitialized()
		if err != nil {
			fatal("Error initializing Kubernetes as the datastore: %s", err)
			terminate()
		}
		log.Info("Kubernetes is initialized as a Calico datastore")
		writeStartupEnv(nodeName, nil, nil)
		return
	}

	// Query the current Node resources.  We update our node resource with
	// updated IP data and use the full list of nodes for validation.
	node := getNode(client, nodeName)

	// Configure and verify the node IP addresses and subnets.
	configureIPsAndSubnets(node)

	// Configure the node AS number.
	configureASNumber(node)

	// Configure IP Pool configuration.
	configureIPPools(client)

	// Check for conflicting node configuration
	checkConflictingNodes(client, node)

	// Apply the updated node resource.
	if _, err := client.Nodes().Apply(node); err != nil {
		fatal("Unable to set node resource configuration: %s", err)
		terminate()
	}

	// Set other Felix config that is not yet in the node resource.
	if err := ensureDefaultConfig(client, node); err != nil {
		fatal("Unable to set global default configuration: %s", err)
		terminate()
	}

	// Write the startup.env file now that we are ready to start other
	// components.
	writeStartupEnv(nodeName, node.Spec.BGP.IPv4Address, node.Spec.BGP.IPv6Address)

	// Tell the user what the name of the node is.
	message("Using node name: %s", nodeName)
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
		// is working.  Getting a specific node is a good option, even
		// if the node does not exist.
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
	}
	message("Datastore connection verified")
}

// writeStartupEnv writes out the startup.env file to set environment variables
// that are required by confd/bird etc. but may not have been passed into the
// container.
func writeStartupEnv(nodeName string, ip, ip6 *net.IP) {
	text := "export HOSTNAME=" + nodeName + "\n"
	text += "export NODENAME=" + nodeName + "\n"
	if ip != nil {
		text += "export IP=" + ip.String() + "\n"
	}
	if ip6 != nil {
		text += "export IP6=" + ip6.String() + "\n"
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
		adm := os.Getenv("IP_AUTODETECT_METHOD")
		node.Spec.BGP.IPv4Address = autoDetectCIDR(adm, 4)

		// We must have an IPv4 address configured for BGP to run.
		if node.Spec.BGP.IPv4Address == nil {
			fatal("Couldn't autodetect a management IPv4 address:")
			message("  -  provide an IP address by configuring one in the node resource, or")
			message("  -  provide an IP address using the IP environment, or")
			message("  -  if auto-detecting, use a different autodetection method.")
			terminate()
		}
	} else {
		if ipv4Env != "" {
			node.Spec.BGP.IPv4Address = parseIPEnvironment("IP", ipv4Env, 4)
		}
		validateIP(node.Spec.BGP.IPv4Address)
	}

	ipv6Env := os.Getenv("IP6")
	if ipv6Env == "autodetect" {
		adm := os.Getenv("IP6_AUTODETECT_METHOD")
		node.Spec.BGP.IPv6Address = autoDetectCIDR(adm, 6)
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
func parseIPEnvironment(envName, envValue string, version int) *net.IP {
	ip := &net.IP{}
	err := ip.UnmarshalText([]byte(envValue))
	if err != nil || ip.Version() != version {
		fatal("Environment does not contain a valid IPv%d address: %s=%s", version, envName, envValue)
		terminate()
	}
	message("Using IPv%d address from environment: %s=%s", ip.Version(), envName, envValue)

	return ip
}

// validateIP checks that the IP address is actually on one of the host
// interfaces and warns if not.
func validateIP(ip *net.IP) {
	// No validation required if no IP address is specified.
	if ip == nil {
		return
	}

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

// autoDetectCIDR auto-detects the IP and Network using the requested
// detection method.
func autoDetectCIDR(detectionMethod string, version int) *net.IP {
	incl := []string{}
	excl := []string{"^docker.*", "^cbr.*", "dummy.*",
		"virbr.*", "lxcbr.*", "veth.*", "lo",
		"cali.*", "tunl.*", "flannel.*"}

	// At the moment, we don't support anything other than the default
	// (blank) auto-detection method.
	if detectionMethod != "" {
		fatal("IP detection method is not supported: %s", detectionMethod)
		terminate()
	}

	iface, cidr, err := autodetection.FilteredEnumeration(incl, excl, version)
	if err != nil {
		message("Unable to auto-detect any valid IPv%d addresses: %s", version, err)
		return nil
	}

	if cidr == nil {
		message("Unable to auto-detect an IPv%d address", version)
		return nil
	}

	message("Using autodetected IPv%d address on interface %s: %s", version, iface.Name, cidr.String())

	return &net.IP{cidr.IP}
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
			message("Using AS number specified in environment: AS=%s", asNum)
			node.Spec.BGP.ASNumber = &asNum
		}
	} else {
		if node.Spec.BGP.ASNumber == nil {
			message("No AS number configured on node resource, using global value")
		} else {
			message("Using AS number configured in node resource: %s", node.Spec.BGP.ASNumber)
		}
	}
}

// configureIPPools ensures that default IP pools are created (unless explicitly
// requested otherwise).
func configureIPPools(client *client.Client) {
	if strings.ToLower(os.Getenv("NO_DEFAULT_POOLS")) == "true" {
		log.Info("Skipping IP pool configuration")
		return
	}

	// Get a list of all IP Pools
	poolList, err := client.IPPools().List(api.IPPoolMetadata{})
	if err != nil {
		fatal("Unable to fetch IP pool list: %s", err)
		terminate()
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

	// Ensure there are pools created for each IP version.
	if !ipv4Present {
		log.Debug("Create default IPv4 IP pool")
		createIPPool(client, DEFAULT_IPV4_POOL_CIDR)
	}
	if !ipv6Present && ipv6Supported() {
		log.Debug("Create default IPv6 IP pool")
		createIPPool(client, DEFAULT_IPV6_POOL_CIDR)
	}
}

// ipv6Supported returns true if IPv6 is supported on this platform.  This performs
// a check on the appropriate Felix parameter and if supported also performs a
// simplistic check of /proc/sys/net/ipv6 (since platforms that do not have IPv6
// compiled in will not have this entry).
func ipv6Supported() bool {
	// First check the Felix parm.
	switch strings.ToLower(os.Getenv("FELIX_IPV6SUPPORT")) {
	case "false", "0", "no", "n", "f":
		log.Info("IPv6 support disabled through environment")
		return false
	}

	// If supported, then also check /proc/sys/net/ipv6.
	_, err := os.Stat("/proc/sys/net/ipv6")
	supported := (err == nil)
	log.Infof("IPv6 supported on this platform: %v", supported)
	return supported
}

// createIPPool creates an IP pool using the specified CIDR string.  This
// method is a no-op if the pool already exists.
func createIPPool(client *client.Client, cs string) {
	_, cidr, _ := net.ParseCIDR(cs)
	version := cidr.Version()

	log.Info("Ensure default IPv%d pool is created", version)
	pool := &api.IPPool{
		Metadata: api.IPPoolMetadata{
			CIDR: *cidr,
		},
		Spec: api.IPPoolSpec{
			NATOutgoing: true,
		},
	}

	// Create the pool.  There is a small chance that another node may
	// beat us to it, so handle the fact that the pool already exists.
	if _, err := client.IPPools().Create(pool); err != nil {
		if _, ok := err.(errors.ErrorResourceAlreadyExists); !ok {
			fatal("Failed to create default IPv%d IP pool: %s", version, err)
			terminate()
		}
	} else {
		message("Created default IPv%d pool (%s) with NAT outgoing enabled", version, cidr)
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
			if theirIPv4 != nil && !theirIPv4.Equal(ourIPv4.IP) {
				warning("Calico node '%s' IPv4 address has changed:",
					theirNode.Metadata.Name)
				message(" -  This could happen if multiple nodes are configured with the same name")
				message(" -  Original IP: %s", theirIPv4)
				message(" -  Updated IP: %s", ourIPv4)
			}
			if theirIPv6 != nil && ourIPv6 != nil && !theirIPv6.Equal(ourIPv6.IP) {
				warning("Calico node '%s' IPv6 address has changed:",
					theirNode.Metadata.Name)
				message(" -  This could happen if multiple nodes are configured with the same name")
				message(" -  Original IP: %s", theirIPv6)
				message(" -  Updated IP: %s", ourIPv6)
			}
			continue
		}

		// Check that other nodes aren't using the same IP addresses.
		// This is an error condition.
		if theirIPv4 != nil && theirIPv4.Equal(ourIPv4.IP) {
			message("Calico node '%s' is already using the IPv4 address %s:",
				theirNode.Metadata.Name, ourIPv4)
			message(" -  Check the node configuration to remove the IP address conflict")
			errored = true
		}
		if theirIPv6 != nil && theirIPv6.Equal(ourIPv6.IP) {
			message("Calico node '%s' is already using the IPv6 address %s:",
				theirNode.Metadata.Name, ourIPv6)
			message(" -  Check the node configuration to remove the IP address conflict")
			errored = true
		}
	}

	if errored {
		terminate()
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
