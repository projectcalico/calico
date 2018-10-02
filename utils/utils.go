// Copyright 2015-2018 Tigera Inc
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/projectcalico/cni-plugin/types"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/sirupsen/logrus"
)

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// DetermineNodename gets the node name, in order of priority:
// 1. Hostname field in NetConf (DEPRECATED).
// 2. Nodename field in NetConf.
// 3. OS Hostname.
func DetermineNodename(conf types.NetConf) string {
	nodename, _ := names.Hostname()
	if conf.Hostname != "" {
		nodename = conf.Hostname
		logrus.Warn("Configuration option 'hostname' is deprecated, use 'nodename' instead.")
	}
	if nff := nodenameFromFile(); nff != "" {
		logrus.Debugf("Read node name from file: %s", nff)
		nodename = nff
	}
	if conf.Nodename != "" {
		logrus.Debugf("Read node name from CNI conf: %s", conf.Nodename)
		nodename = conf.Nodename
	}
	logrus.Debugf("Using node name %s", nodename)
	return nodename
}

// nodenameFromFile reads the /var/lib/calico/nodename file if it exists and
// returns the nodename within.
func nodenameFromFile() string {
	data, err := ioutil.ReadFile("/var/lib/calico/nodename")
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return empty string.
			logrus.Info("File /var/lib/calico/nodename does not exist")
			return ""
		}
		logrus.WithError(err).Error("Failed to read /var/lib/calico/nodename")
		return ""
	}
	return string(data)
}

// CreateOrUpdate creates the WorkloadEndpoint if ResourceVersion is not specified,
// or Update if it's specified.
func CreateOrUpdate(ctx context.Context, client client.Interface, wep *api.WorkloadEndpoint) (*api.WorkloadEndpoint, error) {
	if wep.ResourceVersion != "" {
		return client.WorkloadEndpoints().Update(ctx, wep, options.SetOptions{})
	}

	return client.WorkloadEndpoints().Create(ctx, wep, options.SetOptions{})
}

// CleanUpIPAM calls IPAM plugin to release the IP address.
// It also contains IPAM plugin specific changes needed before calling the plugin.
func CleanUpIPAM(conf types.NetConf, args *skel.CmdArgs, logger *logrus.Entry) error {
	fmt.Fprint(os.Stderr, "Calico CNI releasing IP address\n")
	logger.WithFields(logrus.Fields{"paths": os.Getenv("CNI_PATH"),
		"type": conf.IPAM.Type}).Debug("Looking for IPAM plugin in paths")

	// We need to replace "usePodCidr" with a valid, but dummy podCidr string with "host-local" IPAM.
	if conf.IPAM.Type == "host-local" {
		// host-local IPAM releases the IP by ContainerID, so podCidr isn't really used to release the IP.
		// It just needs a valid CIDR, but it doesn't have to be the CIDR associated with the host.
		const dummyPodCidr = "0.0.0.0/0"
		var stdinData map[string]interface{}
		err := json.Unmarshal(args.StdinData, &stdinData)
		if err != nil {
			return err
		}

		logger.WithField("podCidr", dummyPodCidr).Info("Using a dummy podCidr to release the IP")
		getDummyPodCIDR := func() (string, error) {
			return dummyPodCidr, nil
		}
		err = ReplaceHostLocalIPAMPodCIDRs(logger, stdinData, getDummyPodCIDR)
		if err != nil {
			return err
		}

		args.StdinData, err = json.Marshal(stdinData)
		if err != nil {
			return err
		}
		logger.WithField("stdin", string(args.StdinData)).Debug("Updated stdin data for Delete Cmd")
	}

	err := ipam.ExecDel(conf.IPAM.Type, args.StdinData)

	if err != nil {
		logger.Error(err)
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
func ReplaceHostLocalIPAMPodCIDRs(logger *logrus.Entry, stdinData map[string]interface{}, getPodCIDR func() (string, error)) error {
	ipamData, ok := stdinData["ipam"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("failed to parse host-local IPAM data; was expecting a dict, not: %v", stdinData["ipam"])
	}
	// Older versions of host-local IPAM store a single subnet in the top-level IPAM dict.
	err := replaceHostLocalIPAMPodCIDR(logger, ipamData, getPodCIDR)
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
				err := replaceHostLocalIPAMPodCIDR(logger, r, getPodCIDR)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func replaceHostLocalIPAMPodCIDR(logger *logrus.Entry, rawIpamData interface{}, getPodCidr func() (string, error)) error {
	logrus.WithField("ipamData", rawIpamData).Debug("Examining IPAM data for usePodCidr")
	ipamData, ok := rawIpamData.(map[string]interface{})
	if !ok {
		return fmt.Errorf("failed to parse host-local IPAM data; was expecting a dict, not: %v", rawIpamData)
	}
	subnet, _ := ipamData["subnet"].(string)
	if strings.EqualFold(subnet, "usePodCidr") {
		fmt.Fprint(os.Stderr, "Calico CNI fetching podCidr from Kubernetes\n")
		podCidr, err := getPodCidr()
		if err != nil {
			logger.Info("Failed to getPodCidr")
			return err
		}
		logger.WithField("podCidr", podCidr).Info("Fetched podCidr")
		ipamData["subnet"] = podCidr
		fmt.Fprintf(os.Stderr, "Calico CNI passing podCidr to host-local IPAM: %s\n", podCidr)
	}
	return nil
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
func CreateResultFromEndpoint(wep *api.WorkloadEndpoint) (*current.Result, error) {
	result := &current.Result{}
	for _, v := range wep.Spec.IPNetworks {
		parsedIPConfig := current.IPConfig{}

		ipAddr, ipNet, err := net.ParseCIDR(v)
		if err != nil {
			return nil, err
		}

		parsedIPConfig.Address = *ipNet

		if ipAddr.To4() != nil {
			parsedIPConfig.Version = "4"
		} else {
			parsedIPConfig.Version = "6"
		}

		result.IPs = append(result.IPs, &parsedIPConfig)
	}

	return result, nil
}

// PopulateEndpointNets takes a WorkloadEndpoint and a CNI Result, extracts IP address and mask
// and populates that information into the WorkloadEndpoint.
func PopulateEndpointNets(wep *api.WorkloadEndpoint, result *current.Result) error {
	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin did not return any IP addresses")
	}

	for _, ipNet := range result.IPs {
		if ipNet.Version == "4" {
			ipNet.Address.Mask = net.CIDRMask(32, 32)
		} else {
			ipNet.Address.Mask = net.CIDRMask(128, 128)
		}

		wep.Spec.IPNetworks = append(wep.Spec.IPNetworks, ipNet.Address.String())
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

func GetHandleID(netName string, containerID string, workload string) (string, error) {
	handleID := fmt.Sprintf("%s.%s", netName, containerID)
	logrus.WithFields(logrus.Fields{
		"Network":     netName,
		"ContainerID": containerID,
		"Workload":    workload,
		"HandleID":    handleID,
	}).Debug("Generated IPAM handle")
	return handleID, nil
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
	logrus.Infof("Configured environment: %+v", os.Environ())

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
// CNI ADD execution.
func ReleaseIPAllocation(logger *logrus.Entry, ipamType string, stdinData []byte) {
	logger.Info("Cleaning up IP allocations for failed ADD")
	if err := os.Setenv("CNI_COMMAND", "DEL"); err != nil {
		// Failed to set CNI_COMMAND to DEL.
		logger.Warning("Failed to set CNI_COMMAND=DEL")
	} else {
		if err := ipam.ExecDel(ipamType, stdinData); err != nil {
			// Failed to cleanup the IP allocation.
			logger.Warning("Failed to clean up IP allocations for failed ADD")
		}
	}
}

// Set up logging for both Calico and libcalico using the provided log level,
func ConfigureLogging(logLevel string) {
	if strings.EqualFold(logLevel, "debug") {
		logrus.SetLevel(logrus.DebugLevel)
	} else if strings.EqualFold(logLevel, "info") {
		logrus.SetLevel(logrus.InfoLevel)
	} else {
		// Default level
		logrus.SetLevel(logrus.WarnLevel)
	}

	logrus.SetOutput(os.Stderr)
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
