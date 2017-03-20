// Copyright 2015 Tigera Inc
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
package k8s

import (
	"fmt"
	"net"
	"strings"

	"os"

	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/projectcalico/cni-plugin/utils"
	"github.com/projectcalico/libcalico-go/lib/api"
	k8sbackend "github.com/projectcalico/libcalico-go/lib/backend/k8s"
	cnet "github.com/projectcalico/libcalico-go/lib/net"

	"encoding/json"

	"k8s.io/client-go/kubernetes"
	metav1 "k8s.io/client-go/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	log "github.com/Sirupsen/logrus"
	calicoclient "github.com/projectcalico/libcalico-go/lib/client"
)

// CmdAddK8s performs the "ADD" operation on a kubernetes pod
// Having kubernetes code in its own file avoids polluting the mainline code. It's expected that the kubernetes case will
// more special casing than the mainline code.
func CmdAddK8s(args *skel.CmdArgs, conf utils.NetConf, nodename string, calicoClient *calicoclient.Client, endpoint *api.WorkloadEndpoint) (*types.Result, error) {
	var err error
	var result *types.Result

	k8sArgs := utils.K8sArgs{}
	err = types.LoadArgs(args.Args, &k8sArgs)
	if err != nil {
		return nil, err
	}

	utils.ConfigureLogging(conf.LogLevel)

	workload, orchestrator, err := utils.GetIdentifiers(args)
	if err != nil {
		return nil, err
	}
	logger := utils.CreateContextLogger(workload)
	logger.WithFields(log.Fields{
		"Orchestrator": orchestrator,
		"Node":         nodename,
	}).Info("Extracted identifiers for CmdAddK8s")

	if endpoint != nil {
		// This happens when Docker or the node restarts. K8s calls CNI with the same parameters as before.
		// Do the networking (since the network namespace was destroyed and recreated).
		// There's an existing endpoint - no need to create another. Find the IP address from the endpoint
		// and use that in the response.
		result, err = utils.CreateResultFromEndpoint(endpoint)
		if err != nil {
			return nil, err
		}
		logger.WithField("result", result).Debug("Created result from existing endpoint")
		// If any labels changed whilst the container was being restarted, they will be picked up by the policy
		// controller so there's no need to update the labels here.
	} else {
		client, err := newK8sClient(conf, logger)
		if err != nil {
			return nil, err
		}
		logger.WithField("client", client).Debug("Created Kubernetes client")

		if conf.IPAM.Type == "host-local" && strings.EqualFold(conf.IPAM.Subnet, "usePodCidr") {
			// We've been told to use the "host-local" IPAM plugin with the Kubernetes podCidr for this node.
			// Replace the actual value in the args.StdinData as that's what's passed to the IPAM plugin.
			fmt.Fprintf(os.Stderr, "Calico CNI fetching podCidr from Kubernetes\n")
			var stdinData map[string]interface{}
			if err := json.Unmarshal(args.StdinData, &stdinData); err != nil {
				return nil, err
			}
			podCidr, err := getPodCidr(client, conf, nodename)
			if err != nil {
				return nil, err
			}
			logger.WithField("podCidr", podCidr).Info("Fetched podCidr")
			stdinData["ipam"].(map[string]interface{})["subnet"] = podCidr
			fmt.Fprintf(os.Stderr, "Calico CNI passing podCidr to host-local IPAM: %s\n", podCidr)
			args.StdinData, err = json.Marshal(stdinData)
			if err != nil {
				return nil, err
			}
			logger.WithField("stdin", args.StdinData).Debug("Updated stdin data")
		}

		labels := make(map[string]string)
		annot := make(map[string]string)

		// Only attempt to fetch the labels and annotations from Kubernetes
		// if the policy type has been set to "k8s". This allows users to
		// run the plugin under Kubernetes without needing it to access the
		// Kubernetes API
		if conf.Policy.PolicyType == "k8s" {
			var err error

			labels, annot, err = getK8sLabelsAnnotations(client, k8sArgs)
			if err != nil {
				return nil, err
			}
			logger.WithField("labels", labels).Debug("Fetched K8s labels")
			logger.WithField("annotations", annot).Debug("Fetched K8s annotations")

			// Check for calico IPAM specific annotations and set them if needed.
			if conf.IPAM.Type == "calico-ipam" {

				v4pools := annot["cni.projectcalico.org/ipv4pools"]
				v6pools := annot["cni.projectcalico.org/ipv6pools"]

				if len(v4pools) != 0 || len(v6pools) != 0 {
					var stdinData map[string]interface{}
					if err := json.Unmarshal(args.StdinData, &stdinData); err != nil {
						return nil, err
					}
					var v4PoolSlice, v6PoolSlice []string

					if len(v4pools) > 0 {
						if err := json.Unmarshal([]byte(v4pools), &v4PoolSlice); err != nil {
							logger.WithField("IPv4Pool", v4pools).Error("Error parsing IPv4 IPPools")
							return nil, err
						}

						if _, ok := stdinData["ipam"].(map[string]interface{}); !ok {
							logger.Fatal("Error asserting stdinData type")
							os.Exit(0)
						}
						stdinData["ipam"].(map[string]interface{})["ipv4_pools"] = v4PoolSlice
						logger.WithField("ipv4_pools", v4pools).Debug("Setting IPv4 Pools")
					}
					if len(v6pools) > 0 {
						if err := json.Unmarshal([]byte(v6pools), &v6PoolSlice); err != nil {
							logger.WithField("IPv6Pool", v6pools).Error("Error parsing IPv6 IPPools")
							return nil, err
						}

						if _, ok := stdinData["ipam"].(map[string]interface{}); !ok {
							logger.Fatal("Error asserting stdinData type")
							os.Exit(0)
						}
						stdinData["ipam"].(map[string]interface{})["ipv6_pools"] = v6PoolSlice
						logger.WithField("ipv6_pools", v6pools).Debug("Setting IPv6 Pools")
					}

					newData, err := json.Marshal(stdinData)
					if err != nil {
						logger.WithField("stdinData", stdinData).Error("Error Marshaling data")
						return nil, err
					}
					args.StdinData = newData
					logger.WithField("stdin", args.StdinData).Debug("Updated stdin data")
				}
			}
		}

		ipAddrsNoIpam := annot["cni.projectcalico.org/ipAddrsNoIpam"]
		ipAddrs := annot["cni.projectcalico.org/ipAddrs"]

		// switch based on which annotations are passed or not passed.
		switch {
		case ipAddrs == "" && ipAddrsNoIpam == "":
			// Call IPAM plugin if ipAddrsNoIpam or ipAddrs annotation is not present.
			logger.Debugf("Calling IPAM plugin %s", conf.IPAM.Type)
			result, err = ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
			if err != nil {
				return nil, err
			}
			logger.Debugf("IPAM plugin returned: %+v", result)
		case ipAddrs != "" && ipAddrsNoIpam != "":
			// Can't have both ipAddrs and ipAddrsNoIpam annotations at the same time.
			e := fmt.Errorf("Can't have both annotations: 'ipAddrs' and 'ipAddrsNoIpam' in use at the same time")
			logger.Error(e)
			return nil, e
		case ipAddrsNoIpam != "":
			// ipAddrsNoIpam annotation is set so bypass IPAM, and set the IPs manually.
			result, err = overrideIPAMResult(ipAddrsNoIpam, logger)
			if err != nil {
				return nil, err
			}
			logger.Debugf("Bypassing IPAM to set the result to: %+v", result)
		case ipAddrs != "":
			// When ipAddrs annotation is set, we call out to the configured IPAM plugin
			// requesting the specific IP addresses included in the annotation.
			result, err = ipAddrsResult(ipAddrs, conf, args, logger)
			if err != nil {
				return nil, err
			}
			logger.Debugf("IPAM result set to: %+v", result)
		}

		// Create the endpoint object and configure it.
		endpoint = api.NewWorkloadEndpoint()
		endpoint.Metadata.Name = args.IfName
		endpoint.Metadata.Node = nodename
		endpoint.Metadata.Orchestrator = orchestrator
		endpoint.Metadata.Workload = workload
		endpoint.Metadata.Labels = labels

		// Set the profileID according to whether Kubernetes policy is required.
		// If it's not, then just use the network name (which is the normal behavior)
		// otherwise use one based on the Kubernetes pod's Namespace.
		if conf.Policy.PolicyType == "k8s" {
			endpoint.Spec.Profiles = []string{fmt.Sprintf("k8s_ns.%s", k8sArgs.K8S_POD_NAMESPACE)}
		} else {
			endpoint.Spec.Profiles = []string{conf.Name}
		}

		// Populate the endpoint with the output from the IPAM plugin.
		if err = utils.PopulateEndpointNets(endpoint, result); err != nil {
			// Cleanup IP allocation and return the error.
			utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
			return nil, err
		}
		logger.WithField("endpoint", endpoint).Info("Populated endpoint")
	}
	fmt.Fprintf(os.Stderr, "Calico CNI using IPs: %s\n", endpoint.Spec.IPNetworks)

	// Whether the endpoint existed or not, the veth needs (re)creating.
	hostVethName := k8sbackend.VethNameForWorkload(workload)
	_, contVethMac, err := utils.DoNetworking(args, conf, result, logger, hostVethName)
	if err != nil {
		// Cleanup IP allocation and return the error.
		logger.Errorf("Error setting up networking: %s", err)
		utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
		return nil, err
	}

	mac, err := net.ParseMAC(contVethMac)
	if err != nil {
		// Cleanup IP allocation and return the error.
		logger.Errorf("Error parsing MAC (%s): %s", contVethMac, err)
		utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
		return nil, err
	}
	endpoint.Spec.MAC = &cnet.MAC{HardwareAddr: mac}
	endpoint.Spec.InterfaceName = hostVethName
	logger.WithField("endpoint", endpoint).Info("Added Mac and interface name to endpoint")

	// Write the endpoint object (either the newly created one, or the updated one)
	if _, err := calicoClient.WorkloadEndpoints().Apply(endpoint); err != nil {
		// Cleanup IP allocation and return the error.
		utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
		return nil, err
	}
	logger.Info("Wrote updated endpoint to datastore")

	return result, nil
}

// ipAddrsResult parses the ipAddrs annotation and calls the configured IPAM plugin for
// each IP passed to it by setting the IP field in CNI_ARGS, and returns the result of calling the IPAM plugin.
// Example annotation value string: "[\"10.0.0.1\", \"2001:db8::1\"]"
func ipAddrsResult(ipAddrs string, conf utils.NetConf, args *skel.CmdArgs, logger *log.Entry) (*types.Result, error) {

	logger.Infof("Parsing annotation \"cni.projectcalico.org/ipAddrs\":%s", ipAddrs)
	ips, err := parseIPAddrs(ipAddrs, logger)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse IPs %s for annotation \"cni.projectcalico.org/ipAddrs\": %s", ipAddrs, err)
	}

	// annotation value can't be empty.
	if len(ips) == 0 {
		return nil, fmt.Errorf("Annotation \"cni.projectcalico.org/ipAddrs\" specified but empty")
	}

	result := types.Result{}

	// Go through all the IPs passed in as annotation value and call IPAM plugin
	// for each, and populate the result variable with IP4 and/or IP6 IPs returned
	// from the IPAM plugin. We also make sure there is only one IPv4 and/or one IPv6
	// passed in, since CNI spec only supports one of each right now.
	for _, ip := range ips {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			logger.WithField("IP", ip).Error("Invalid IP format")
			return nil, fmt.Errorf("Invalid IP format: %s", ip)
		}

		// It's an IPv6 address if ip.To4 is nil.
		if ipAddr.To4() == nil {
			// CNI spec only allows one IPv4 and one IPv6 at the moment.
			// So if we see more than one of IPv4 or IPv6 then we throw an error.
			// If/when CNI spec supports more than one IP, we can loosen this requirement.
			if result.IP6 != nil {
				e := fmt.Errorf("Can not have more than one IPv6 address in ipAddrs annotation")
				logger.Error(e)
				return nil, e
			}

			// Call callIPAMWithIP with the ip address.
			r, err := callIPAMWithIP(ipAddr, conf, args, logger)
			if err != nil {
				return nil, fmt.Errorf("Error getting IP from IPAM: %s", err)
			}

			// Set the IP6 part of the result from the type.Result returned by the IPAM plugin.
			result.IP6 = r.IP6
			logger.Debugf("Adding IPv6: %s to result", ipAddr.String())
		} else {
			// It's an IPv4 address.
			if result.IP4 != nil {
				e := fmt.Errorf("Can not have more than one IPv4 address in ipAddrs annotation")
				logger.Error(e)
				return nil, e
			}

			// Call callIPAMWithIP with the ip address.
			r, err := callIPAMWithIP(ipAddr, conf, args, logger)
			if err != nil {
				return nil, fmt.Errorf("Error getting IP from IPAM: %s", err)
			}

			// Set the IP4 part of the result from the type.Result returned by the IPAM plugin.
			result.IP4 = r.IP4
			logger.Debugf("Adding IPv4: %s to result", ipAddr.String())
		}
	}

	return &result, nil
}

// callIPAMWithIP sets CNI_ARGS with the IP and calls the IPAM plugin with it
// to get types.Result and then it unsets the IP field from CNI_ARGS ENV var,
// so it doesn't pollute the subsequent requests.
func callIPAMWithIP(ip net.IP, conf utils.NetConf, args *skel.CmdArgs, logger *log.Entry) (*types.Result, error) {

	// Save the original value of the CNI_ARGS ENV var for backup.
	originalArgs := os.Getenv("CNI_ARGS")
	logger.Debugf("Original CNI_ARGS=%s", originalArgs)

	ipamArgs := struct {
		types.CommonArgs
		IP net.IP `json:"ip,omitempty"`
	}{}

	if err := types.LoadArgs(args.Args, &ipamArgs); err != nil {
		return nil, err
	}

	if ipamArgs.IP != nil {
		logger.Errorf("'IP' variable already set in CNI_ARGS environment variable.")
	}

	// Request the provided IP address using the IP CNI_ARG.
	// See: https://github.com/containernetworking/cni/blob/master/CONVENTIONS.md#cni_args for more info.
	newArgs := originalArgs + ";IP=" + ip.String()
	logger.Debugf("New CNI_ARGS=%s", newArgs)

	// Set CNI_ARGS to the new value.
	err := os.Setenv("CNI_ARGS", newArgs)
	if err != nil {
		return nil, fmt.Errorf("Error setting CNI_ARGS environment variable: %v", err)
	}

	// Run the IPAM plugin.
	logger.Debugf("Calling IPAM plugin %s", conf.IPAM.Type)
	r, err := ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
	if err != nil {
		// Restore the CNI_ARGS ENV var to it's original value,
		// so the subsequent calls don't get polluted by the old IP value.
		if err := os.Setenv("CNI_ARGS", originalArgs); err != nil {
			logger.Errorf("Error setting CNI_ARGS environment variable: %v", err)
		}
		return nil, err
	}
	logger.Debugf("IPAM plugin returned: %+v", r)

	// Restore the CNI_ARGS ENV var to it's original value,
	// so the subsequent calls don't get polluted by the old IP value.
	if err := os.Setenv("CNI_ARGS", originalArgs); err != nil {
		// Need to clean up IP allocation if this step doesn't succeed.
		utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
		logger.Errorf("Error setting CNI_ARGS environment variable: %v", err)
		return nil, err
	}

	return r, nil
}

// overrideIPAMResult generates types.Result like the one produced by IPAM plugin,
// but sets IP field manually since IPAM is bypassed with this annotation.
// Example annotation value string: "[\"10.0.0.1\", \"2001:db8::1\"]"
func overrideIPAMResult(ipAddrsNoIpam string, logger *log.Entry) (*types.Result, error) {

	logger.Infof("Parsing annotation \"cni.projectcalico.org/ipAddrsNoIpam\":%s", ipAddrsNoIpam)
	ips, err := parseIPAddrs(ipAddrsNoIpam, logger)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse IPs %s for annotation \"cni.projectcalico.org/ipAddrsNoIpam\": %s", ipAddrsNoIpam, err)
	}

	// annotation value can't be empty.
	if len(ips) == 0 {
		return nil, fmt.Errorf("Annotation \"cni.projectcalico.org/ipAddrsNoIpam\" specified but empty")
	}

	result := types.Result{}

	// Go through all the IPs passed in as annotation value and populate
	// the result variable with IP4 and/or IP6 IPs.
	// We also make sure there is only one IPv4 and/or one IPv6 passed in,
	// since CNI spec only supports one of each right now.
	for _, ip := range ips {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			logger.WithField("IP", ip).Error("Invalid IP format")
			return nil, fmt.Errorf("Invalid IP format: %s", ip)
		}

		// It's an IPv6 address if ip.To4 is nil.
		if ipAddr.To4() == nil {
			// CNI spec only allows one IPv4 and one IPv6 at the moment.
			// So if we see more than one of IPv4 or IPv6 then we throw an error.
			// If/when CNI spec supports more than one IP, we can loosen this requirement.
			if result.IP6 != nil {
				e := fmt.Errorf("Can not have more than one IPv6 address in ipAddrsNoIpam annotation")
				logger.Error(e)
				return nil, e
			}
			result.IP6 = &types.IPConfig{
				IP: net.IPNet{
					IP:   ipAddr,
					Mask: net.CIDRMask(128, 128),
				},
			}
			logger.Debugf("Adding IPv6: %s to result", ipAddr.String())
		} else {
			// It's an IPv4 address.
			if result.IP4 != nil {
				e := fmt.Errorf("Can not have more than one IPv4 address in ipAddrsNoIpam annotation")
				logger.Error(e)
				return nil, e
			}
			result.IP4 = &types.IPConfig{
				IP: net.IPNet{
					IP:   ipAddr,
					Mask: net.CIDRMask(32, 32),
				},
			}
			logger.Debugf("Adding IPv4: %s to result", ipAddr.String())
		}
	}

	return &result, nil
}

// parseIPAddrs is a utility function that parses string of IPs in json format that are
// passed in as a string and returns a slice of string with IPs.
// It also makes sure the slice isn't empty.
func parseIPAddrs(ipAddrsStr string, logger *log.Entry) ([]string, error) {
	var ips []string

	err := json.Unmarshal([]byte(ipAddrsStr), &ips)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse '%s' as JSON: %s", ipAddrsStr, err)
	}

	logger.Debugf("IPs parsed: %v", ips)

	return ips, nil
}

func newK8sClient(conf utils.NetConf, logger *log.Entry) (*kubernetes.Clientset, error) {
	// Some config can be passed in a kubeconfig file
	kubeconfig := conf.Kubernetes.Kubeconfig

	// Config can be overridden by config passed in explicitly in the network config.
	configOverrides := &clientcmd.ConfigOverrides{}

	// If an API root is given, make sure we're using using the name / port rather than
	// the full URL. Earlier versions of the config required the full `/api/v1/` extension,
	// so split that off to ensure compatibility.
	conf.Policy.K8sAPIRoot = strings.Split(conf.Policy.K8sAPIRoot, "/api/")[0]

	var overridesMap = []struct {
		variable *string
		value    string
	}{
		{&configOverrides.ClusterInfo.Server, conf.Policy.K8sAPIRoot},
		{&configOverrides.AuthInfo.ClientCertificate, conf.Policy.K8sClientCertificate},
		{&configOverrides.AuthInfo.ClientKey, conf.Policy.K8sClientKey},
		{&configOverrides.ClusterInfo.CertificateAuthority, conf.Policy.K8sCertificateAuthority},
		{&configOverrides.AuthInfo.Token, conf.Policy.K8sAuthToken},
	}

	// Using the override map above, populate any non-empty values.
	for _, override := range overridesMap {
		if override.value != "" {
			*override.variable = override.value
		}
	}

	// Also allow the K8sAPIRoot to appear under the "kubernetes" block in the network config.
	if conf.Kubernetes.K8sAPIRoot != "" {
		configOverrides.ClusterInfo.Server = conf.Kubernetes.K8sAPIRoot
	}

	// Use the kubernetes client code to load the kubeconfig file and combine it with the overrides.
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
		configOverrides).ClientConfig()
	if err != nil {
		return nil, err
	}

	logger.Debugf("Kubernetes config %v", config)

	// Create the clientset
	return kubernetes.NewForConfig(config)
}

func getK8sLabelsAnnotations(client *kubernetes.Clientset, k8sargs utils.K8sArgs) (map[string]string, map[string]string, error) {
	pod, err := client.Pods(string(k8sargs.K8S_POD_NAMESPACE)).Get(fmt.Sprintf("%s", k8sargs.K8S_POD_NAME), metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	labels := pod.Labels
	if labels == nil {
		labels = make(map[string]string)
	}

	labels["calico/k8s_ns"] = fmt.Sprintf("%s", k8sargs.K8S_POD_NAMESPACE)

	return labels, pod.Annotations, nil
}

func getPodCidr(client *kubernetes.Clientset, conf utils.NetConf, nodename string) (string, error) {
	// Pull the node name out of the config if it's set. Defaults to nodename
	if conf.Kubernetes.NodeName != "" {
		nodename = conf.Kubernetes.NodeName
	}

	node, err := client.Nodes().Get(nodename, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	if node.Spec.PodCIDR == "" {
		err = fmt.Errorf("No podCidr for node %s", nodename)
		return "", err
	} else {
		return node.Spec.PodCIDR, nil
	}
}
