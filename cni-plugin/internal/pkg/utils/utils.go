// Copyright (c) 2015-2020 Tigera, Inc. All rights reserved.
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
package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/azure"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// DetermineNodename gets the node name, in order of priority:
// 1. Nodename field in NetConf
// 2. Nodename from the file /var/lib/calico/nodename
// 3. Hostname field in NetConf (DEPRECATED).
// 4. OS Hostname.
func DetermineNodename(conf types.NetConf) (nodename string) {
	if conf.Nodename != "" {
		logrus.Debugf("Read node name from CNI conf: %s", conf.Nodename)
		nodename = conf.Nodename
	} else if nff := nodenameFromFile(conf.NodenameFile); nff != "" {
		logrus.Debugf("Read node name from file: %s", nff)
		nodename = nff
	} else if conf.Hostname != "" {
		nodename = conf.Hostname
		logrus.Warn("Configuration option 'hostname' is deprecated, use 'nodename' instead")
	} else {
		nodename, _ = names.Hostname()
		logrus.Debugf("Read node name from OS Hostname")
	}

	logrus.Debugf("Using node name %s", nodename)
	return
}

// nodenameFromFile reads the /var/lib/calico/nodename file if it exists and
// returns the nodename within.
func nodenameFromFile(filename string) string {
	if filename == "" {
		filename = "/var/lib/calico/nodename"
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return empty string.
			logrus.Infof("File %s does not exist", filename)
			return ""
		}
		logrus.WithError(err).Errorf("Failed to read %s", filename)
		return ""
	}
	return string(data)
}

// MTUFromFile reads the /var/lib/calico/mtu file if it exists and
// returns the MTU within.
func MTUFromFile(filename string) (int, error) {
	if filename == "" {
		filename = "/var/lib/calico/mtu"
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return zero.
			logrus.Infof("File %s does not exist", filename)
			return 0, nil
		}
		logrus.WithError(err).Errorf("Failed to read %s", filename)
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// CreateOrUpdate creates the WorkloadEndpoint if ResourceVersion is not specified,
// or Update if it's specified.
func CreateOrUpdate(ctx context.Context, client client.Interface, wep *api.WorkloadEndpoint) (*api.WorkloadEndpoint, error) {
	if wep.ResourceVersion != "" {
		return client.WorkloadEndpoints().Update(ctx, wep, options.SetOptions{})
	}

	return client.WorkloadEndpoints().Create(ctx, wep, options.SetOptions{})
}

// AddIPAM calls through to the configured IPAM plugin.
// It also contains IPAM plugin specific logic based on the configured plugin.
func AddIPAM(conf types.NetConf, args *skel.CmdArgs, logger *logrus.Entry) (*cniv1.Result, error) {
	// Check if we're configured to use the Azure IPAM plugin.
	var an *azure.AzureNetwork
	if conf.IPAM.Type == "azure-vnet-ipam" {
		// Load the azure network configuration, if any exists. Then, use
		// that configuration to mutate the config we'll pass to the IPAM plugin.
		logger.Info("Configured to use Azure IPAM, check for subnet")
		an = &azure.AzureNetwork{Name: conf.Name}
		if err := an.Load(); err != nil {
			return nil, err
		}
		if err := azure.MutateConfigAdd(args, *an); err != nil {
			return nil, err
		}
	}

	// Actually call the IPAM plugin.
	logger.Debugf("Calling IPAM plugin %s", conf.IPAM.Type)
	ipamResult, err := ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
	if err != nil {
		return nil, err
	}
	logger.Debugf("IPAM plugin returned: %+v", ipamResult)

	// Convert the IPAM result into the current version.
	result, err := cniv1.NewResultFromResult(ipamResult)
	if err != nil {
		return nil, err
	}
	if len(result.IPs) == 0 {
		return nil, errors.New("IPAM plugin returned missing IP config")
	}

	// If we're using the Azure plugin, then write azure network and endpoint information here.
	// We'll need this information on delete so we can clean up any allocated IPs.
	if an != nil {
		// Store the Azure network data so that we can access it on subsequent calls.
		subnetPrefix := result.IPs[0].Address
		subnetPrefix.IP = subnetPrefix.IP.Mask(subnetPrefix.Mask)
		an.Subnets = []string{subnetPrefix.String()}
		if err := an.Write(); err != nil {
			return nil, err
		}
		logger.Infof("Stored azure subnet on disk: %s", subnetPrefix)

		// Store the Azure endpoint data for use on delete.
		var ips []string
		for _, ip := range result.IPs {
			ips = append(ips, ip.Address.IP.String())
		}
		ae := azure.AzureEndpoint{
			Network:     conf.Name,
			ContainerID: args.ContainerID,
			Interface:   args.IfName,
			Addresses:   ips,
		}
		if err := ae.Write(); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// DeleteIPAM calls IPAM plugin to release the IP address.
// It also contains IPAM plugin specific logic based on the configured plugin,
// and is the logical counterpart to AddIPAM.
func DeleteIPAM(conf types.NetConf, args *skel.CmdArgs, logger *logrus.Entry) error {
	logger.Info("Calico CNI releasing IP address")
	logger.WithFields(logrus.Fields{"paths": os.Getenv("CNI_PATH"),
		"type": conf.IPAM.Type}).Debug("Looking for IPAM plugin in paths")

	var ae *azure.AzureEndpoint
	if conf.IPAM.Type == "host-local" {
		// We need to replace "usePodCidr" with a valid, but dummy podCidr string with "host-local" IPAM.
		// host-local IPAM releases the IP by ContainerID, so podCidr isn't really used to release the IP.
		// It just needs a valid CIDR, but it doesn't have to be the CIDR associated with the host.
		dummyPodCidrv4 := "0.0.0.0/0"
		dummyPodCidrv6 := "::/0"
		var stdinData map[string]interface{}
		err := json.Unmarshal(args.StdinData, &stdinData)
		if err != nil {
			return err
		}

		logger.WithFields(logrus.Fields{"podCidrv4": dummyPodCidrv4,
			"podCidrv6": dummyPodCidrv6}).Info("Using dummy podCidrs to release the IPs")
		getDummyPodCIDR := func() (string, string, error) {
			return dummyPodCidrv4, dummyPodCidrv6, nil
		}
		err = ReplaceHostLocalIPAMPodCIDRs(logger, stdinData, getDummyPodCIDR)
		if err != nil {
			return err
		}

		args.StdinData, err = json.Marshal(stdinData)
		if err != nil {
			return err
		}
		logger.Debug("Updated stdin data for Delete Cmd")
	} else if conf.IPAM.Type == "azure-vnet-ipam" {
		// The azure-vnet-ipam plugin expects two values to be passed in the CNI config in order to
		// successfully clean up: ipAddress and subnet. Populate these based on data stored to disk.
		logger.Info("Configured to use Azure IPAM, load network and endpoint")
		an := &azure.AzureNetwork{Name: conf.Name}
		if err := an.Load(); err != nil {
			return err
		}
		ae = &azure.AzureEndpoint{Network: conf.Name, ContainerID: args.ContainerID, Interface: args.IfName}
		if err := ae.Load(); err != nil {
			return err
		}
		if len(ae.Addresses) == 0 {
			// If we couldn't find this endpoint, then simply return successfully.
			logger.WithField("AzureEndpoint", ae).Infof("No endpoint addresses, skip IPAM release")
			return nil
		}
		if err := azure.MutateConfigDel(args, *an, *ae); err != nil {
			return err
		}
	}

	// Call the CNI plugin.
	err := ipam.ExecDel(conf.IPAM.Type, args.StdinData)
	if err != nil {
		logger.Error(err)
	} else if ae != nil {
		// Clean up any Azure endpoint data now that we've claened up the IPAM allocation.
		// However, don't do this if the IPAM release failed - otherwise we'll lose information we need
		// in order to release the address.
		if err := ae.Delete(); err != nil {
			logger.WithError(err).Errorf("Error deleting Azure endpoint")
		}
	}

	return err
}

// ReplaceHostLocalIPAMPodCIDRs extracts the host-local IPAM config section and replaces our special-case "usePodCidr"
// subnet value with pod CIDR retrieved by the passed-in getPodCIDR function.  Typically, the passed-in function
// would access the datastore to retrieve the podCIDR. However, for tear-down we use a dummy value that returns
// 0.0.0.0/0.
//
// To make sure that unknown fields are round-tripped, we manipulate the JSON as maps and slices rather than by
// unmarshaling it into a struct.  The structure of the JSON is as follows; we support replacing usePodCidr in
// either the "ipam" dict or its nested ranges section:
//
//    {
//      "cniVersion": "%s",
//      ...
//      "ipam": {
//        "type": "host-local",
//        "subnet": "usePodCidr",
//        "ranges": [
//          [
//             {
//               "subnet": "usePodCidr"
//             }
//          ]
//        ]
//      }
//      ...
//    }
func ReplaceHostLocalIPAMPodCIDRs(logger *logrus.Entry, stdinData map[string]interface{}, getPodCIDRs func() (string, string, error)) error {
	ipamData, ok := stdinData["ipam"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("failed to parse host-local IPAM data; was expecting a dict, not: %v", stdinData["ipam"])
	}
	// Older versions of host-local IPAM store a single subnet in the top-level IPAM dict.
	err := replaceHostLocalIPAMPodCIDR(logger, ipamData, getPodCIDRs)
	if err != nil {
		return err
	}
	// Newer versions store one or more subnets in the "ranges" list:
	untypedRanges := ipamData["ranges"]
	if untypedRanges != nil {
		rangeSets, ok := untypedRanges.([]interface{})
		if !ok {
			return fmt.Errorf("failed to parse host-local IPAM ranges section; was expecting a list, not: %v",
				ipamData["ranges"])
		}
		for _, urs := range rangeSets {
			rs, ok := urs.([]interface{})
			if !ok {
				return fmt.Errorf("failed to parse host-local IPAM range set; was expecting a list, not: %v", rs)
			}
			for _, r := range rs {
				err := replaceHostLocalIPAMPodCIDR(logger, r, getPodCIDRs)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func replaceHostLocalIPAMPodCIDR(logger *logrus.Entry, rawIpamData interface{}, getPodCidrs func() (string, string, error)) error {
	logrus.WithField("ipamData", rawIpamData).Debug("Examining IPAM data for usePodCidr")
	ipamData, ok := rawIpamData.(map[string]interface{})
	if !ok {
		return fmt.Errorf("failed to parse host-local IPAM data; was expecting a dict, not: %v", rawIpamData)
	}
	subnet, _ := ipamData["subnet"].(string)

	if strings.EqualFold(subnet, "usePodCidr") {
		ipv4Cidr, _, err := getPodCidrs()
		if err != nil {
			logger.Errorf("Failed to getPodCidrs")
			return err
		}
		if ipv4Cidr == "" {
			return errors.New("usePodCidr found but there is no IPv4 CIDR configured")
		}

		ipamData["subnet"] = ipv4Cidr
		subnet = ipv4Cidr
		logger.Infof("Calico CNI passing podCidr to host-local IPAM: %s", ipv4Cidr)
	}

	if strings.EqualFold(subnet, "usePodCidrIPv6") {
		_, ipv6Cidr, err := getPodCidrs()
		if err != nil {
			logger.Errorf("Failed to ipv6 getPodCidrs")
			return err
		}
		if ipv6Cidr == "" {
			return errors.New("usePodCidrIPv6 found but there is no IPv6 CIDR configured")
		}

		ipamData["subnet"] = ipv6Cidr
		logger.Infof("Calico CNI passing podCidrv6 to host-local IPAM: %s", ipv6Cidr)
		return nil
	}

	// updateHostLocalIPAMDataForOS is only required for Windows and only ipv4 is supported
	err := updateHostLocalIPAMDataForOS(subnet, ipamData)
	if err != nil {
		return err
	}

	return nil
}

// This function will update host-local IPAM data based on input from cni.conf
func UpdateHostLocalIPAMDataForWindows(subnet string, ipamData map[string]interface{}) error {
	if len(subnet) == 0 {
		return nil
	}
	//Checks whether the ip is valid or not
	logrus.Info("Updating host-local IPAM configuration to reserve IPs for Windows bridge.")
	ip, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return err
	}
	//process only if we have ipv4 subnet
	//VXLAN networks on Windows do not support dual-stack https://kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/#ipv6-networking
	if ip.To4() != nil {
		//get Expected start and end range for given CIDR
		expStartRange, expEndRange := getIPRanges(ip, ipnet)
		//validate ranges given in cni.conf
		rangeStart, _ := ipamData["rangeStart"].(string)
		startRange, err := validateRangeOrSetDefault(rangeStart, expStartRange, ipnet, true)
		if err != nil {
			return err
		}
		ipamData["rangeStart"] = startRange

		rangeEnd, _ := ipamData["rangeEnd"].(string)
		endRange, err := validateRangeOrSetDefault(rangeEnd, expEndRange, ipnet, false)
		if err != nil {
			return err
		}
		ipamData["rangeEnd"] = endRange
	}
	return nil
}

func getIPRanges(ip net.IP, ipnet *net.IPNet) (string, string) {

	ip = ip.To4()
	// Mask the address
	ip.Mask(ipnet.Mask)
	// OR in the start address.
	ip[len(ip)-1] |= 3
	startRange := ip.String()
	// Now find the broadbcast address and decrement by 1 to get endRange
	for i := 0; i < len(ip); i++ {
		ip[i] |= (^ipnet.Mask[i])
	}
	ip[len(ip)-1] -= 1

	endRange := ip.String()
	return startRange, endRange
}

func validateStartRange(startRange net.IP, expStartRange net.IP) (net.IP, error) {
	//check if we have ipv4 ip address
	startRange = startRange.To4()
	expStartRange = expStartRange.To4()
	if startRange == nil || expStartRange == nil {
		return nil, fmt.Errorf("Invalid ip address")
	}
	if bytes.Compare([]byte(startRange), []byte(expStartRange)) < 0 {
		//if ip is not in given range,return default
		return expStartRange, nil
	}
	return startRange, nil

}

func validateEndRange(endRange net.IP, expEndRange net.IP) (net.IP, error) {
	//check if we have ipv4 ip address
	endRange = endRange.To4()
	expEndRange = expEndRange.To4()
	if endRange == nil || expEndRange == nil {
		return nil, fmt.Errorf("Invalid ip address")
	}
	if bytes.Compare([]byte(endRange), []byte(expEndRange)) > 0 {
		//if ip is not in given range,return default
		return expEndRange, nil
	}
	return endRange, nil
}

// This function will validate and return an ip within expected start/end range
func validateRangeOrSetDefault(rangeData string, expRange string, ipnet *net.IPNet, isRangeStart bool) (string, error) {
	var parsedIP *cnet.IP
	var expRangeIP *cnet.IP
	var ip net.IP
	//Parse IP and convert into 4 bytes address
	if expRangeIP = cnet.ParseIP(expRange); expRangeIP == nil {
		return "", fmt.Errorf("expRange contains invalid ip")
	}
	if len(rangeData) > 0 {
		//Checks whether the ip is valid or not
		if parsedIP = cnet.ParseIP(rangeData); parsedIP == nil {
			return "", fmt.Errorf("range contains invalid ip")
		} else if ipnet.Contains(parsedIP.IP) { //Checks whether the ip belongs to subnet
			if isRangeStart {
				//check if Startrange should be in expected limit
				ip, _ = validateStartRange(parsedIP.IP, expRangeIP.IP)
			} else {
				//check if Endrange exceeds expected limit
				ip, _ = validateEndRange(parsedIP.IP, expRangeIP.IP)
			}
			return ip.String(), nil
		}
	}
	//return default range
	return expRangeIP.IP.String(), nil

}

// ValidateNetworkName checks that the network name meets felix's expectations
func ValidateNetworkName(name string) error {
	matched, err := regexp.MatchString(`^[a-zA-Z0-9_\.\-]+$`, name)
	if err != nil {
		return err
	}
	if !matched {
		return errors.New("invalid characters detected in the given network name. " +
			"Only letters a-z, numbers 0-9, and symbols _.- are supported")
	}
	return nil
}

// SanitizeMesosLabel converts a string from a valid mesos label to a valid Calico label.
// Mesos labels have no restriction outside of being unicode.
func SanitizeMesosLabel(s string) string {
	// Inspired by:
	// https://github.com/projectcalico/libcalico-go/blob/2ff29bed865c4b364d4fcf1ad214b2bd8d9b4afa/lib/upgrade/converters/names.go#L39-L58
	invalidChar := regexp.MustCompile("[^-_.a-zA-Z0-9]+")
	dotDashSeq := regexp.MustCompile("[.-]*[.][.-]*")
	trailingLeadingDotsDashes := regexp.MustCompile("^[.-]*(.*?)[.-]*$")

	// -  Convert [/] to .
	s = strings.Replace(s, "/", ".", -1)

	// -  Convert any other invalid chars
	s = invalidChar.ReplaceAllString(s, "-")

	// Convert any multi-byte sequence of [-.] with at least one [.] to a single .
	s = dotDashSeq.ReplaceAllString(s, ".")

	// Extract the trailing and leading dots and dashes.   This should always match even if
	// the matched substring is empty.  The second item in the returned submatch
	// slice is the captured match group.
	submatches := trailingLeadingDotsDashes.FindStringSubmatch(s)
	s = submatches[1]
	return s
}

// AddIgnoreUnknownArgs appends the 'IgnoreUnknown=1' option to CNI_ARGS before calling the IPAM plugin. Otherwise, it will
// complain about the Kubernetes arguments. See https://github.com/kubernetes/kubernetes/pull/24983
func AddIgnoreUnknownArgs() error {
	cniArgs := "IgnoreUnknown=1"
	if os.Getenv("CNI_ARGS") != "" {
		cniArgs = fmt.Sprintf("%s;%s", cniArgs, os.Getenv("CNI_ARGS"))
	}
	return os.Setenv("CNI_ARGS", cniArgs)
}

// CreateResultFromEndpoint takes a WorkloadEndpoint, extracts IP information
// and populates that into a CNI Result.
func CreateResultFromEndpoint(wep *api.WorkloadEndpoint) (*cniv1.Result, error) {
	result := &cniv1.Result{}
	for _, v := range wep.Spec.IPNetworks {
		parsedIPConfig := cniv1.IPConfig{}

		_, ipNet, err := net.ParseCIDR(v)
		if err != nil {
			return nil, err
		}

		parsedIPConfig.Address = *ipNet

		result.IPs = append(result.IPs, &parsedIPConfig)
	}

	return result, nil
}

// PopulateEndpointNets takes a WorkloadEndpoint and a CNI Result, extracts IP address and mask
// and populates that information into the WorkloadEndpoint.
func PopulateEndpointNets(wep *api.WorkloadEndpoint, result *cniv1.Result) error {
	var copyIpNet net.IPNet
	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin did not return any IP addresses")
	}

	for _, ipNet := range result.IPs {
		copyIpNet = net.IPNet{IP: ipNet.Address.IP, Mask: ipNet.Address.Mask}
		if ipNet.Address.IP.To4() != nil {
			copyIpNet.Mask = net.CIDRMask(32, 32)
		} else {
			copyIpNet.Mask = net.CIDRMask(128, 128)
		}

		wep.Spec.IPNetworks = append(wep.Spec.IPNetworks, copyIpNet.String())
	}

	return nil
}

type WEPIdentifiers struct {
	Namespace string
	WEPName   string
	names.WorkloadEndpointIdentifiers
}

// GetIdentifiers takes CNI command arguments, and extracts identifiers i.e. pod name, pod namespace,
// container ID, endpoint(container interface name) and orchestratorID based on the orchestrator.
func GetIdentifiers(args *skel.CmdArgs, nodename string) (*WEPIdentifiers, error) {
	// Determine if running under k8s by checking the CNI args
	k8sArgs := types.K8sArgs{}
	if err := cnitypes.LoadArgs(args.Args, &k8sArgs); err != nil {
		return nil, err
	}
	logrus.Debugf("Getting WEP identifiers with arguments: %s, for node %s", args.Args, nodename)
	logrus.Debugf("Loaded k8s arguments: %v", k8sArgs)

	epIDs := WEPIdentifiers{}
	epIDs.ContainerID = args.ContainerID
	epIDs.Node = nodename
	epIDs.Endpoint = args.IfName

	// Check if the workload is running under Kubernetes.
	if string(k8sArgs.K8S_POD_NAMESPACE) != "" && string(k8sArgs.K8S_POD_NAME) != "" {
		epIDs.Orchestrator = "k8s"
		epIDs.Pod = string(k8sArgs.K8S_POD_NAME)
		epIDs.Namespace = string(k8sArgs.K8S_POD_NAMESPACE)
	} else {
		epIDs.Orchestrator = "cni"
		epIDs.Pod = ""
		// For any non-k8s orchestrator we set the namespace to default.
		epIDs.Namespace = "default"

		// Warning: CNITestArgs is used for test purpose only and subject to change without prior notice.
		CNITestArgs := types.CNITestArgs{}
		if err := cnitypes.LoadArgs(args.Args, &CNITestArgs); err == nil {
			// Set namespace with the value passed by CNI test args.
			if string(CNITestArgs.CNI_TEST_NAMESPACE) != "" {
				epIDs.Namespace = string(CNITestArgs.CNI_TEST_NAMESPACE)
			}
		}
	}

	return &epIDs, nil
}

func GetHandleID(netName, containerID, workload string) string {
	handleID := fmt.Sprintf("%s.%s", netName, containerID)

	logrus.WithFields(logrus.Fields{
		"HandleID":    handleID,
		"Network":     netName,
		"Workload":    workload,
		"ContainerID": containerID,
	}).Debug("Generated IPAM handle")
	return handleID
}

func CreateClient(conf types.NetConf) (client.Interface, error) {
	if err := ValidateNetworkName(conf.Name); err != nil {
		return nil, err
	}

	// Use the config file to override environment variables.
	// These variables will be loaded into the client config.
	if conf.EtcdAuthority != "" {
		if err := os.Setenv("ETCD_AUTHORITY", conf.EtcdAuthority); err != nil {
			return nil, err
		}
	}
	if conf.EtcdEndpoints != "" {
		if err := os.Setenv("ETCD_ENDPOINTS", conf.EtcdEndpoints); err != nil {
			return nil, err
		}
	}
	if conf.EtcdDiscoverySrv != "" {
		if err := os.Setenv("ETCD_DISCOVERY_SRV", conf.EtcdDiscoverySrv); err != nil {
			return nil, err
		}
	}
	if conf.EtcdScheme != "" {
		if err := os.Setenv("ETCD_SCHEME", conf.EtcdScheme); err != nil {
			return nil, err
		}
	}
	if conf.EtcdKeyFile != "" {
		if err := os.Setenv("ETCD_KEY_FILE", conf.EtcdKeyFile); err != nil {
			return nil, err
		}
	}
	if conf.EtcdCertFile != "" {
		if err := os.Setenv("ETCD_CERT_FILE", conf.EtcdCertFile); err != nil {
			return nil, err
		}
	}
	if conf.EtcdCaCertFile != "" {
		if err := os.Setenv("ETCD_CA_CERT_FILE", conf.EtcdCaCertFile); err != nil {
			return nil, err
		}
	}
	if conf.DatastoreType != "" {
		if err := os.Setenv("DATASTORE_TYPE", conf.DatastoreType); err != nil {
			return nil, err
		}
	}

	// Set Kubernetes specific variables for use with the Kubernetes libcalico backend.
	if conf.Kubernetes.Kubeconfig != "" {
		if err := os.Setenv("KUBECONFIG", conf.Kubernetes.Kubeconfig); err != nil {
			return nil, err
		}
	}
	if conf.Kubernetes.K8sAPIRoot != "" {
		if err := os.Setenv("K8S_API_ENDPOINT", conf.Kubernetes.K8sAPIRoot); err != nil {
			return nil, err
		}
	}
	if conf.Policy.K8sAuthToken != "" {
		if err := os.Setenv("K8S_API_TOKEN", conf.Policy.K8sAuthToken); err != nil {
			return nil, err
		}
	}

	// Load the client config from the current environment.
	clientConfig, err := apiconfig.LoadClientConfig("")
	if err != nil {
		return nil, err
	}

	// Create a new client.
	calicoClient, err := client.New(*clientConfig)
	if err != nil {
		return nil, err
	}
	return calicoClient, nil
}

// ReleaseIPAllocation is called to cleanup IPAM allocations if something goes wrong during
// CNI ADD execution. It forces the CNI_COMMAND to be DEL.
func ReleaseIPAllocation(logger *logrus.Entry, conf types.NetConf, args *skel.CmdArgs) {
	logger.Info("Cleaning up IP allocations for failed ADD")
	if err := os.Setenv("CNI_COMMAND", "DEL"); err != nil {
		// Failed to set CNI_COMMAND to DEL.
		logger.Warning("Failed to set CNI_COMMAND=DEL")
	} else {
		if err := DeleteIPAM(conf, args, logger); err != nil {
			// Failed to cleanup the IP allocation.
			logger.Warning("Failed to clean up IP allocations for failed ADD")
		}
	}
}

// Set up logging for both Calico and libcalico using the provided log level,
func ConfigureLogging(conf types.NetConf) {
	if strings.EqualFold(conf.LogLevel, "debug") {
		logrus.SetLevel(logrus.DebugLevel)
	} else if strings.EqualFold(conf.LogLevel, "info") {
		logrus.SetLevel(logrus.InfoLevel)
	} else if strings.EqualFold(conf.LogLevel, "error") {
		logrus.SetLevel(logrus.ErrorLevel)
	} else {
		// Default level
		logrus.SetLevel(logrus.InfoLevel)
	}

	writers := []io.Writer{os.Stderr}
	// Set the log output to write to a log file if specified.
	if conf.LogFilePath != "" {
		// Create the path for the log file if it does not exist
		err := os.MkdirAll(filepath.Dir(conf.LogFilePath), 0755)
		if err != nil {
			logrus.WithError(err).Errorf("Failed to create path for CNI log file: %v", filepath.Dir(conf.LogFilePath))
		}

		// Create file logger with log file rotation.
		fileLogger := &lumberjack.Logger{
			Filename:   conf.LogFilePath,
			MaxSize:    100,
			MaxAge:     30,
			MaxBackups: 10,
		}

		// Set the max size if exists. Defaults to 100 MB.
		if conf.LogFileMaxSize != 0 {
			fileLogger.MaxSize = conf.LogFileMaxSize
		}

		// Set the max time in days to retain a log file before it is cleaned up. Defaults to 30 days.
		if conf.LogFileMaxAge != 0 {
			fileLogger.MaxAge = conf.LogFileMaxAge
		}

		// Set the max number of log files to retain before they are cleaned up. Defaults to 10.
		if conf.LogFileMaxCount != 0 {
			fileLogger.MaxBackups = conf.LogFileMaxCount
		}

		writers = append(writers, fileLogger)
	}

	mw := io.MultiWriter(writers...)

	logrus.SetOutput(mw)
}

// ResolvePools takes an array of CIDRs or IP Pool names and resolves it to a slice of pool CIDRs.
func ResolvePools(ctx context.Context, c client.Interface, pools []string, isv4 bool) ([]cnet.IPNet, error) {
	// First, query all IP pools. We need these so we can resolve names to CIDRs.
	pl, err := c.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		return nil, err
	}

	// Iterate through the provided pools. If it parses as a CIDR, just use that.
	// If it does not parse as a CIDR, then attempt to lookup an IP pool with a matching name.
	result := []cnet.IPNet{}
	for _, p := range pools {
		_, cidr, err := net.ParseCIDR(p)
		if err != nil {
			// Didn't parse as a CIDR - check if it's the name
			// of a configured IP pool.
			for _, ipp := range pl.Items {
				if ipp.Name == p {
					// Found a match. Use the CIDR from the matching pool.
					_, cidr, err = net.ParseCIDR(ipp.Spec.CIDR)
					if err != nil {
						return nil, fmt.Errorf("failed to parse IP pool cidr: %s", err)
					}
					logrus.Infof("Resolved pool name %s to cidr %s", ipp.Name, cidr)
				}
			}

			if cidr == nil {
				// Unable to resolve this pool to a CIDR - return an error.
				return nil, fmt.Errorf("error parsing pool %q: %s", p, err)
			}
		}

		ip := cidr.IP
		if isv4 && ip.To4() == nil {
			return nil, fmt.Errorf("%q isn't a IPv4 address", ip)
		}
		if !isv4 && ip.To4() != nil {
			return nil, fmt.Errorf("%q isn't a IPv6 address", ip)
		}
		result = append(result, cnet.IPNet{IPNet: *cidr})
	}
	return result, nil
}
