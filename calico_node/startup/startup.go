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
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/projectcalico/calico/calico_node/calicoclient"
	"github.com/projectcalico/calico/calico_node/startup/autodetection"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v2"
	client "github.com/projectcalico/libcalico-go/lib/clientv2"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	defaultLogSeverity        = "info"
	globalFelixConfigName     = "default"
	globalClusterInfoName     = "default"
	felixNodeConfigNamePrefix = "node."
)

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

	// Create the Calico API cli.
	cfg, cli := calicoclient.CreateClient()

	ctx := context.Background()

	// An explicit value of true is required to wait for the datastore.
	if os.Getenv("WAIT_FOR_DATASTORE") == "true" {
		waitForConnection(ctx, cli)
		log.Info("Datastore is ready")
	} else {
		message("Skipping datastore connection test")
	}

	// Query the current Node resources.  We update our node resource with
	// updated IP data and use the full list of nodes for validation.
	node := getNode(ctx, cli, nodeName)

	// If Calico is running in policy only mode we don't need to write
	// BGP related details to the Node.
	if os.Getenv("CALICO_NETWORKING_BACKEND") != "none" {
		// Configure and verify the node IP addresses and subnets.
		checkConflicts := configureIPsAndSubnets(node)

		// If we report an IP change (v4 or v6) we should verify there are no
		// conflicts between Nodes.
		if checkConflicts && os.Getenv("DISABLE_NODE_IP_CHECK") != "true" {
			checkConflictingNodes(ctx, cli, node)
		}

		// Configure the node AS number.
		configureASNumber(node)
	}

	// Check expected filesystem
	ensureFilesystemAsExpected()

	// Apply the updated node resource.
	if _, err := CreateOrUpdate(ctx, cli, node); err != nil {
		fatal("Unable to set node resource configuration: %s", err)
		terminate()
	}

	// Configure IP Pool configuration.
	configureIPPools(ctx, cli)

	// Set default configuration required for the cluster.
	if err := ensureDefaultConfig(ctx, cfg, cli, node); err != nil {
		fatal("Unable to set global default configuration: %s", err)
		terminate()
	}

	// Write the startup.env file now that we are ready to start other
	// components.
	writeStartupEnv(nodeName)

	// Tell the user what the name of the node is.
	message("Using node name: %s", nodeName)
}

// CreateOrUpdate creates the Node if ResourceVersion is not specified,
// or Update if it's specified.
func CreateOrUpdate(ctx context.Context, client client.Interface, node *api.Node) (*api.Node, error) {
	if node.ResourceVersion != "" {
		return client.Nodes().Update(ctx, node, options.SetOptions{})
	}

	return client.Nodes().Create(ctx, node, options.SetOptions{})
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
func waitForConnection(ctx context.Context, c client.Interface) {
	message("Checking datastore connection")
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
				fatal("Connection to the datastore is unauthorized")
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
	message("Datastore connection verified")
}

// writeStartupEnv writes out the startup.env file to set environment variables
// that are required by confd/bird etc. but may not have been passed into the
// container.
func writeStartupEnv(nodeName string) {
	text := "export NODENAME=" + nodeName + "\n"

	// Write out the startup.env file to ensure required environments are
	// set (which they might not otherwise be).
	if err := ioutil.WriteFile("startup.env", []byte(text), 0666); err != nil {
		log.WithError(err).Info("Unable to write to startup.env")
		fatal("Unable to write to local filesystem")
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
			fatal("Unable to access datastore to query node configuration")
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
func configureIPsAndSubnets(node *api.Node) bool {
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
			fatal("Couldn't autodetect a management IPv4 address:")
			message("  -  provide an IPv4 address by configuring one in the node resource, or")
			message("  -  provide an IPv4 address using the IP environment, or")
			message("  -  if auto-detecting, use a different autodetection method.")
			terminate()
		} else {
			// No IPv4 autodetected, but a previous one was configured.
			// Tell the user we are leaving the value unchanged.  We
			// will validate that the IP matches one on the interface.
			warning("Autodetection of IPv4 address failed, keeping existing value: %s", node.Spec.BGP.IPv4Address)
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
			node.Spec.BGP.IPv6Address = cidr.String()
		} else if node.Spec.BGP.IPv6Address == "" {
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
			warning("Autodetection of IPv6 address failed, keeping existing value: %s", node.Spec.BGP.IPv6Address)
			validateIP(node.Spec.BGP.IPv6Address)
		}
	} else {
		if ipv6Env != "" {
			node.Spec.BGP.IPv6Address = parseIPEnvironment("IP6", ipv6Env, 6)
		}
		validateIP(node.Spec.BGP.IPv6Address)
	}

	// Detect if we've seen the IP address change, and flag that we need to check for conflicting Nodes
	if oldIpv4 == "" || node.Spec.BGP.IPv4Address != oldIpv4 {
		log.Info("Node IPv4 changed, will check for conflicts")
		return true
	}
	if (oldIpv6 == "" && node.Spec.BGP.IPv6Address != "") || (oldIpv6 != "" && node.Spec.BGP.IPv6Address != oldIpv6) {
		log.Info("Node IPv6 changed, will check for conflicts")
		return true
	}

	return false
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
		fatal("Environment does not contain a valid IPv%d address: %s=%s", version, envName, envValue)
		terminate()
	}
	message("Using IPv%d address from environment: %s=%s", ip.Version(), envName, envValue)

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
		fatal("Failed to parse autodetected CIDR '%s'", ipn)
		terminate()
	}

	// Get a complete list of interfaces with their addresses and check if
	// the IP address can be found.
	ifaces, err := autodetection.GetInterfaces(nil, nil, ipAddr.Version())
	if err != nil {
		fatal("Unable to query host interfaces: %s", err)
		terminate()
	}
	if len(ifaces) == 0 {
		message("No interfaces found for validating IP configuration")
	}

	for _, i := range ifaces {
		for _, c := range i.Cidrs {
			if ipAddr.Equal(c.IP) {
				message("IPv%d address %s discovered on interface %s", ipAddr.Version(), ipAddr.String(), i.Name)
				return
			}
		}
	}
	warning("Unable to confirm IPv%d address %s is assigned to this host", ipAddr.Version(), ipAddr)
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
	fatal("Invalid IP autodection method: %s", method)
	terminate()
	return nil
}

// autoDetectCIDRFirstFound auto-detects the first valid Network it finds across
// all interfaces (excluding common known internal interface names).
func autoDetectCIDRFirstFound(version int) *cnet.IPNet {
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
func autoDetectCIDRByInterface(ifaceRegexes []string, version int) *cnet.IPNet {
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
func autoDetectCIDRByReach(dest string, version int) *cnet.IPNet {
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
func autoDetectCIDRBySkipInterface(ifaceRegexes []string, version int) *cnet.IPNet {
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

// getIPv6Pool return a random generated ULA IPv6 prefix generated following rfc4193#section-3.2.2
// The Pool is generated with a concatenation of Unix timestamps + fe80:: base IPv6 hased with SHA-1
func getIPv6Pool() string {
	var eui string
	ifaces, _ := net.Interfaces()
IfaceLoop:
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			eui = fmt.Sprintln(ip)
			if eui[0:4] == "fe80" && len(eui) == 26 {
				// We get out the Loop at the first fe80:: IPv6
				break IfaceLoop
			}
		}
	}
	if eui != "" {
		date := fmt.Sprint(time.Now().Unix())
		d := []byte(date)
		h := sha1.New()
		h.Write(d)
		h.Write([]byte(strings.Replace(eui, ":", "", -1)))
		sum := hex.EncodeToString(h.Sum(nil))
		// IPv6 Random Pool generation
		buf := &bytes.Buffer{}
		buf.WriteString("fd")
		buf.WriteString(sum[30:32])
		buf.WriteString(":")
		buf.WriteString(sum[32:36])
		buf.WriteString(":")
		buf.WriteString(sum[36:40])
		buf.WriteString(":0000::/64")
		t, _ := fmt.Print(buf.String())
		final := strconv.Itoa(t)
		return final
	} else {
		warning("Unable to fetch fe80: IPv6 address, Is IPv6 enabled ?")
		final := "fd80:24e2:f998:72d6::/64"
		return final

	}
}

// configureIPPools ensures that default IP pools are created (unless explicitly
// requested otherwise).
func configureIPPools(ctx context.Context, client client.Interface) {
	// Read in environment variables for use here and later.
	ipv4Pool := os.Getenv("CALICO_IPV4POOL_CIDR")
	ipv6Pool := fmt.Sprintf(getIPv6Pool())

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
	poolList, err := client.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		fatal("Unable to fetch IP pool list: %s", err)
		terminate()
		return // not really needed but allows testing to function
	}

	// Check for IPv4 and IPv6 pools.
	ipv4Present := false
	ipv6Present := false
	for _, p := range poolList.Items {
		ip, _, err := cnet.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			warning("Error parsing CIDR '%s'. Skipping the IPPool.", p.Spec.CIDR)
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
		fatal("Invalid CIDR specified in CALICO_IPV4POOL_CIDR '%s'", ipv4Pool)
		terminate()
		return // not really needed but allows testing to function
	}

	// Read IPV6 CIDR from env if set and parse then check it for errors
	if ipv6Pool == "" {
		ipv6Pool = DEFAULT_IPV6_POOL_CIDR
	}
	_, ipv6Cidr, err := cnet.ParseCIDR(ipv6Pool)
	if err != nil || ipv6Cidr.Version() != 6 {
		fatal("Invalid CIDR specified in CALICO_IPV6POOL_CIDR '%s'", ipv6Pool)
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
		fatal("Unrecognized IPIP mode specified in CALICO_IPV4POOL_IPIP '%s'", ipipModeName)
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
func checkConflictingNodes(ctx context.Context, client client.Interface, node *api.Node) {
	// Get the full set of nodes.
	var nodes []api.Node
	if nodeList, err := client.Nodes().List(ctx, options.ListOptions{}); err != nil {
		fatal("Unable to query node confguration: %s", err)
		terminate()
	} else {
		nodes = nodeList.Items
	}

	ourIPv4, _, err := cnet.ParseCIDROrIP(node.Spec.BGP.IPv4Address)
	if err != nil && node.Spec.BGP.IPv4Address != "" {
		fatal("Error parsing IPv4 CIDR '%s' for node '%s': %s", node.Spec.BGP.IPv4Address, node.Name, err)
		terminate()
	}
	ourIPv6, _, err := cnet.ParseCIDROrIP(node.Spec.BGP.IPv6Address)
	if err != nil && node.Spec.BGP.IPv6Address != "" {
		fatal("Error parsing IPv6 CIDR '%s' for node '%s': %s", node.Spec.BGP.IPv6Address, node.Name, err)
		terminate()
	}

	errored := false
	for _, theirNode := range nodes {
		if theirNode.Spec.BGP == nil {
			// Skip nodes that don't have BGP configured.  We know
			// that this node does have BGP since we only perform
			// this check after configuring BGP.
			continue
		}

		theirIPv4, _, err := cnet.ParseCIDROrIP(theirNode.Spec.BGP.IPv4Address)
		if err != nil && theirNode.Spec.BGP.IPv4Address != "" {
			fatal("Error parsing IPv4 CIDR '%s' for node '%s': %s", theirNode.Spec.BGP.IPv4Address, theirNode.Name, err)
			terminate()
		}

		theirIPv6, _, err := cnet.ParseCIDROrIP(theirNode.Spec.BGP.IPv6Address)
		if err != nil && theirNode.Spec.BGP.IPv6Address != "" {
			fatal("Error parsing IPv6 CIDR '%s' for node '%s': %s", theirNode.Spec.BGP.IPv6Address, theirNode.Name, err)
			terminate()
		}

		// If this is our node (based on the name), check if the IP
		// addresses have changed.  If so warn the user as it could be
		// an indication of multiple nodes using the same name.  This
		// is not an error condition as the IPs could actually change.
		if theirNode.Name == node.Name {
			if theirIPv4 != nil && ourIPv4 != nil && !theirIPv4.IP.Equal(ourIPv4.IP) {
				warning("Calico node '%s' IPv4 address has changed:",
					theirNode.Name)
				message(" -  This could happen if multiple nodes are configured with the same name")
				message(" -  Original IP: %s", theirIPv4.String())
				message(" -  Updated IP: %s", ourIPv4.String())
			}
			if theirIPv6 != nil && ourIPv6 != nil && !theirIPv6.IP.Equal(ourIPv6.IP) {
				warning("Calico node '%s' IPv6 address has changed:",
					theirNode.Name)
				message(" -  This could happen if multiple nodes are configured with the same name")
				message(" -  Original IP: %s", theirIPv6.String())
				message(" -  Updated IP: %s", ourIPv6.String())
			}
			continue
		}

		// Check that other nodes aren't using the same IP addresses.
		// This is an error condition.
		if theirIPv4 != nil && ourIPv4 != nil && theirIPv4.IP.Equal(ourIPv4.IP) {
			message("Calico node '%s' is already using the IPv4 address %s:",
				theirNode.Name, ourIPv4.String())
			message(" -  Check the node configuration to remove the IP address conflict")
			errored = true
		}
		if theirIPv6 != nil && ourIPv6 != nil && theirIPv6.IP.Equal(ourIPv6.IP) {
			message("Calico node '%s' is already using the IPv6 address %s:",
				theirNode.Name, ourIPv6.String())
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
func ensureDefaultConfig(ctx context.Context, cfg *apiconfig.CalicoAPIConfig, c client.Interface, node *api.Node) error {
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
			interval := 0
			newFelixConf.Spec.ReportingIntervalSecs = &interval
			newFelixConf.Spec.LogSeverityScreen = defaultLogSeverity
			_, err = c.FelixConfigurations().Create(ctx, newFelixConf, options.SetOptions{})
			if err != nil {
				log.WithError(err).WithField("FelixConfig", newFelixConf).Errorf("Error creating Felix global config")
				return err
			}
		} else {
			log.WithError(err).WithField("FelixConfig", globalFelixConfigName).Errorf("Error getting Felix global config")
			return err
		}
	} else {
		updateNeeded := false
		if felixConf.Spec.ReportingIntervalSecs == nil {
			interval := 0
			felixConf.Spec.ReportingIntervalSecs = &interval
			updateNeeded = true
		} else {
			log.WithField("ReportingIntervalSecs", felixConf.Spec.ReportingIntervalSecs).Debug("Global Felix value already assigned")
		}

		if felixConf.Spec.LogSeverityScreen == "" {
			felixConf.Spec.LogSeverityScreen = defaultLogSeverity
			updateNeeded = true
		} else {
			log.WithField("LogSeverityScreen", felixConf.Spec.LogSeverityScreen).Debug("Global Felix value already assigned")
		}

		if updateNeeded {
			_, err = c.FelixConfigurations().Update(ctx, felixConf, options.SetOptions{})
			if err = checkConflictError(err); err != nil {
				log.WithError(err).WithField("FelixConfig", felixConf).Errorf("Error updating Felix global config")
				return err
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
				newFelixNodeCfg.Spec.DefaultEndpointToHostAction = "RETURN"
				_, err = c.FelixConfigurations().Create(ctx, newFelixNodeCfg, options.SetOptions{})
				if err != nil {
					log.WithError(err).WithField("FelixConfig", newFelixNodeCfg).Errorf("Error creating Felix node config")
					return err
				}
			} else {
				log.WithError(err).WithField("FelixConfig", felixNodeConfigNamePrefix).Errorf("Error getting Felix node config")
				return err
			}
		} else {
			if felixNodeCfg.Spec.DefaultEndpointToHostAction == "" {
				felixNodeCfg.Spec.DefaultEndpointToHostAction = "RETURN"
				_, err = c.FelixConfigurations().Update(ctx, felixNodeCfg, options.SetOptions{})
				if err = checkConflictError(err); err != nil {
					log.WithError(err).WithField("FelixConfig", felixNodeCfg).Errorf("Error updating Felix node config")
					return err
				}
			} else {
				log.WithField("DefaultEndpointToHostAction", felixNodeCfg.Spec.DefaultEndpointToHostAction).Debug("Host Felix value already assigned")
			}
		}
	}

	// Make sure Cluster information is populated in the datastore
	// and populate the values if they're not already there in the datastore
	// we populate the ClusterType with the type in CLUSTER_TYPE, Calico version
	// and cluster GUID here.
	if err := ensureClusterInformation(ctx, c, cfg); err != nil {
		return err
	}

	return nil
}

// ensureClusterInformation ensures that the ClusterInformation fields i.e. ClusterType, CalicoVersion and ClusterGUID
// is assigned, and create/update it with appropriate values if it's not.
// In case of ClusterType, we merge the values if it's already assigned and is different from what it's suppose to be.
func ensureClusterInformation(ctx context.Context, c client.Interface, cfg *apiconfig.CalicoAPIConfig) error {
	// Get the ClusterType from ENV var. This is set from the manifest.
	clusterType := os.Getenv("CLUSTER_TYPE")

	// Append "kdd" last if the datastoreType is 'kubernetes'.
	if cfg.Spec.DatastoreType == apiconfig.Kubernetes {
		// If clusterType is already set then append ",kdd" at the end.
		if clusterType != "" {
			// Trim the trailing ",", if any.
			clusterType = strings.TrimSuffix(clusterType, ",")
			// Append "kdd" very last thing in the list.
			clusterType = fmt.Sprintf("%s,%s", clusterType, "kdd")
		} else {
			clusterType = "kdd"
		}
	}

	// Store the Calico Version as a global felix config setting.
	clusterInfo, err := c.ClusterInformation().Get(ctx, globalClusterInfoName, options.GetOptions{})
	if err != nil {
		// Create the default config if it doesn't already exist.
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			newClusterInfo := api.NewClusterInformation()
			newClusterInfo.Name = globalClusterInfoName
			newClusterInfo.Spec.CalicoVersion = VERSION
			newClusterInfo.Spec.ClusterType = clusterType
			newClusterInfo.Spec.ClusterGUID = fmt.Sprintf("%s", hex.EncodeToString(uuid.NewV4().Bytes()))
			_, err = c.ClusterInformation().Create(ctx, newClusterInfo, options.SetOptions{})
			if err != nil {
				log.WithError(err).WithField("ClusterInformation", newClusterInfo).Errorf("Error creating cluster information config")
				return err
			}
		} else {
			log.WithError(err).WithField("ClusterInformation", globalClusterInfoName).Errorf("Error getting cluster information config")
			return err
		}
	} else {
		updateNeeded := false
		// Only update the version if it's different from what we have.
		if clusterInfo.Spec.CalicoVersion != VERSION {
			clusterInfo.Spec.CalicoVersion = VERSION
			updateNeeded = true
		} else {
			log.WithField("CalicoVersion", clusterInfo.Spec.CalicoVersion).Debug("Calico version value already assigned")
		}

		if clusterInfo.Spec.ClusterGUID == "" {
			clusterInfo.Spec.ClusterGUID = fmt.Sprintf("%s", hex.EncodeToString(uuid.NewV4().Bytes()))
			updateNeeded = true
		} else {
			log.WithField("ClusterGUID", clusterInfo.Spec.ClusterGUID).Debug("Cluster GUID value already set")
		}

		if clusterInfo.Spec.ClusterType == "" {
			clusterInfo.Spec.ClusterType = clusterType
			updateNeeded = true
		} else {
			datastoreClusterTypeSlice := strings.Split(clusterInfo.Spec.ClusterType, ",")
			localClusterTypeSlice := strings.Split(clusterType, ",")

			for _, lct := range localClusterTypeSlice {
				found := false
				for _, x := range datastoreClusterTypeSlice {
					if lct == x {
						found = true
						break
					}
				}
				if !found {
					datastoreClusterTypeSlice = append(datastoreClusterTypeSlice, lct)
					updateNeeded = true
				}
			}

			if updateNeeded {
				clusterInfo.Spec.ClusterType = strings.Join(datastoreClusterTypeSlice, ",")
			}
		}

		if updateNeeded {
			_, err = c.ClusterInformation().Update(ctx, clusterInfo, options.SetOptions{})
			if err = checkConflictError(err); err != nil {
				log.WithError(err).WithField("ClusterInformation", clusterInfo).Errorf("Error updating cluster information config")
				return err
			}
		}
	}

	return nil
}

// checkConflictError checks to see if the given error is of the type ErrorResourceUpdateConflict
// and ignore it if so. This is to allow our global configs to ignore conflict from multiple Nodes
// trying to set the same value at the same time.
func checkConflictError(err error) error {
	if conflict, ok := err.(cerrors.ErrorResourceUpdateConflict); ok {
		log.Infof("Ignoring conflict when setting value %s", conflict.Identifier)
		return nil
	}
	return err
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
