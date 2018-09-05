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
	"errors"
	"fmt"
	"net"
	"strings"

	"os"

	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/projectcalico/cni-plugin/utils"
	"github.com/projectcalico/libcalico-go/lib/api"
	k8sbackend "github.com/projectcalico/libcalico-go/lib/backend/k8s"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"

	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	calicoclient "github.com/projectcalico/libcalico-go/lib/client"
	log "github.com/sirupsen/logrus"
)

// CmdAddK8s performs the "ADD" operation on a kubernetes pod
// Having kubernetes code in its own file avoids polluting the mainline code. It's expected that the kubernetes case will
// more special casing than the mainline code.
func CmdAddK8s(args *skel.CmdArgs, conf utils.NetConf, nodename string, calicoClient *calicoclient.Client, endpoint *api.WorkloadEndpoint) (*current.Result, error) {
	var err error
	var result *current.Result

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

	// Allocate the IP and update/create the endpoint. Do this even if the endpoint already exists and has an IP
	// allocation. The kubelet will send a DEL call for any old containers and we'll clean up the old IPs then.
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
		logger.WithField("stdin", string(args.StdinData)).Debug("Updated stdin data")
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
				logger.WithField("stdin", string(args.StdinData)).Debug("Updated stdin data")
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
		ipamResult, err := ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
		if err != nil {
			return nil, err
		}
		logger.Debugf("IPAM plugin returned: %+v", ipamResult)

		// Convert IPAM result into current Result.
		// IPAM result has a bunch of fields that are optional for an IPAM plugin
		// but required for a CNI plugin, so this is to populate those fields.
		// See CNI Spec doc for more details.
		result, err = current.NewResultFromResult(ipamResult)
		if err != nil {
			utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
			return nil, err
		}

		if len(result.IPs) == 0 {
			utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
			return nil, errors.New("IPAM plugin returned missing IP config")
		}

	case ipAddrs != "" && ipAddrsNoIpam != "":
		// Can't have both ipAddrs and ipAddrsNoIpam annotations at the same time.
		e := fmt.Errorf("Can't have both annotations: 'ipAddrs' and 'ipAddrsNoIpam' in use at the same time")
		logger.Error(e)
		return nil, e
	case ipAddrsNoIpam != "":
		// ipAddrsNoIpam annotation is set so bypass IPAM, and set the IPs manually.
		overriddenResult, err := overrideIPAMResult(ipAddrsNoIpam, logger)
		if err != nil {
			return nil, err
		}
		logger.Debugf("Bypassing IPAM to set the result to: %+v", overriddenResult)

		// Convert overridden IPAM result into current Result.
		// This method fill in all the empty fields necessory for CNI output according to spec.
		result, err = current.NewResultFromResult(overriddenResult)
		if err != nil {
			return nil, err
		}

		if len(result.IPs) == 0 {
			return nil, errors.New("Failed to build result")
		}

	case ipAddrs != "":
		// If the endpoint already exists, we need to attempt to release the previous IP addresses here
		// since the ADD call will fail when it tries to reallocate the same IPs. releaseIPAddrs assumes
		// that Calico IPAM is in use, which is OK here since only Calico IPAM supports the ipAddrs
		// annotation.
		if endpoint != nil {
			logger.Info("Endpoint already exists and ipAddrs is set. Release any old IPs")
			if err := releaseIPAddrs(endpoint.Spec.IPNetworks, calicoClient, logger); err != nil {
				return nil, fmt.Errorf("failed to release ipAddrs: %s", err)
			}
		}

		// When ipAddrs annotation is set, we call out to the configured IPAM plugin
		// requesting the specific IP addresses included in the annotation.
		result, err = ipAddrsResult(ipAddrs, conf, args, logger)
		if err != nil {
			return nil, err
		}
		logger.Debugf("IPAM result set to: %+v", result)
	}

	// Create the endpoint object and configure it.
	if endpoint == nil {
		endpoint = api.NewWorkloadEndpoint()
	}
	endpoint.Metadata.Name = args.IfName
	endpoint.Metadata.Node = nodename
	endpoint.Metadata.Orchestrator = orchestrator
	endpoint.Metadata.Workload = workload
	endpoint.Metadata.Labels = labels
	endpoint.Spec.IPNetworks = []cnet.IPNet{}

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
	fmt.Fprintf(os.Stderr, "Calico CNI using IPs: %s\n", endpoint.Spec.IPNetworks)

	// releaseIPAM cleans up any IPAM allocations for this endpoint.
	releaseIPAM := func() {
		logger := logger.WithField("endpointIPs", endpoint.Spec.IPNetworks)
		utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
	}

	// Whether the endpoint existed or not, the veth needs (re)creating.
	hostVethName := k8sbackend.VethNameForWorkload(workload)
	_, contVethMac, err := utils.DoNetworking(args, conf, result, logger, hostVethName)
	if err != nil {
		logger.WithError(err).Error("Error setting up networking")
		releaseIPAM()
		return nil, err
	}

	mac, err := net.ParseMAC(contVethMac)
	if err != nil {
		logger.WithError(err).WithField("mac", mac).Error("Error parsing container MAC")
		releaseIPAM()
		return nil, err
	}
	endpoint.Spec.MAC = &cnet.MAC{HardwareAddr: mac}
	endpoint.Spec.InterfaceName = hostVethName
	endpoint.Metadata.ActiveInstanceID = args.ContainerID
	logger.WithField("endpoint", endpoint).Info("Added Mac, interface name, and active container ID to endpoint")

	// Write the endpoint object (either the newly created one, or the updated one)
	if _, err := calicoClient.WorkloadEndpoints().Apply(endpoint); err != nil {
		logger.WithError(err).Error("Error creating/updating endpoint in datastore.")
		releaseIPAM()
		return nil, err
	}
	logger.Info("Wrote updated endpoint to datastore")

	return result, nil
}

// CmdDelK8s performs the "DEL" operation on a kubernetes pod.
// The following logic only applies to kubernetes since it sends multiple DELs for the same
// endpoint. See: https://github.com/kubernetes/kubernetes/issues/44100
// We store CNI_CONTAINERID as ActiveInstanceID in WEP Metadata for k8s,
// so in this function we need to get the WEP and make sure we check if ContainerID and ActiveInstanceID
// are the same before deleting the pod being deleted.
func CmdDelK8s(c *calicoclient.Client, ep api.WorkloadEndpointMetadata, args *skel.CmdArgs, conf utils.NetConf, logger *log.Entry) error {
	wep, err := c.WorkloadEndpoints().Get(ep)
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			// Could not connect to datastore (connection refused, unauthorized, etc.)
			// so we have no way of knowing/checking ActiveInstanceID. To protect the endpoint
			// from false DEL, we return the error without deleting/cleaning up.
			return err
		}

		// We can talk to the datastore but WEP doesn't exist in there,
		// but we still want to go ahead with the clean up. So, log a warning and continue with the clean up.
		logger.WithField("WorkloadEndpoint", ep).Warning("WorkloadEndpoint does not exist in the datastore, moving forward with the clean up")
	} else if wep.Metadata.ActiveInstanceID != "" && args.ContainerID != wep.Metadata.ActiveInstanceID {
		// If the ContainerID is populated and doesn't match the CNI_CONATINERID provided for this execution, then
		// we shouldn't delete the workload endpoint. We identify workload endpoints based on pod name and namespace, which means
		// we can receive DEL commands for an old sandbox for a currently running pod. However, we key IPAM allocations based on the
		// CNI_CONTAINERID, so we should still do that below for this case.
		logger.WithField("WorkloadEndpoint", wep).Warning("CNI_ContainerID does not match WorkloadEndpoint ActiveInstanceID so ignoring the DELETE cmd.")
	} else if err = c.WorkloadEndpoints().Delete(wep.Metadata); err != nil {
		// Delete the WorkloadEndpoint object from the datastore.
		// In case of k8s, where we are deleting the WEP we got from the Datastore,
		// this Delete is a Compare-and-Delete, so if *any* field in the WEP changed from
		// the time we get WEP until here then the Delete operation will fail.
		switch err := err.(type) {
		case cerrors.ErrorResourceDoesNotExist:
			// Log and proceed with the clean up if WEP doesn't exist.
			logger.WithField("endpoint", wep).Info("Endpoint object does not exist, no need to clean up.")
		case cerrors.ErrorResourceUpdateConflict:
			// This case means the WEP object was modified between the time we did the Get and now,
			// so it's not a safe Compare-and-Delete operation, so log and abort with the error.
			// Returning an error here is with the assumption that k8s (kubelet) retries deleting again.
			logger.WithField("endpoint", wep).Warning("Error deleting endpoint: endpoint was modified before it could be deleted.")
			return fmt.Errorf("Error deleting endpoint: endpoint was modified before it could be deleted: %v", err)
		case cerrors.ErrorOperationNotSupported:
			// KDD does not support WorkloadEndpoint deletion, the WEP is backed by the Pod and the
			// deletion will be handled by Kubernetes. This error can be ignored.
			logger.WithField("endpoint", wep).Info("Endpoint deletion will be handled by Kubernetes deletion of the Pod.")
		default:
			return err
		}
	}

	// Release the IP address by calling the configured IPAM plugin.
	logger.Info("Releasing IP address(es)")
	ipamErr := utils.CleanUpIPAM(conf, args, logger)

	// Clean up namespace by removing the interfaces.
	logger.Info("Cleaning up netns")
	err = utils.CleanUpNamespace(args, logger)
	if err != nil {
		return err
	}

	// Return the IPAM error if there was one. The IPAM error will be lost if there was also an error in cleaning up
	// the device or endpoint, but crucially, the user will know the overall operation failed.
	if ipamErr != nil {
		return ipamErr
	}

	logger.Info("Teardown processing complete.")
	return nil
}

// ipAddrsResult parses the ipAddrs annotation and calls the configured IPAM plugin for
// each IP passed to it by setting the IP field in CNI_ARGS, and returns the result of calling the IPAM plugin.
// Example annotation value string: "[\"10.0.0.1\", \"2001:db8::1\"]"
func ipAddrsResult(ipAddrs string, conf utils.NetConf, args *skel.CmdArgs, logger *log.Entry) (*current.Result, error) {
	logger.Infof("Parsing annotation \"cni.projectcalico.org/ipAddrs\":%s", ipAddrs)

	// We need to make sure there is only one IPv4 and/or one IPv6
	// passed in, since CNI spec only supports one of each right now.
	ipList, err := validateAndExtractIPs(ipAddrs, "cni.projectcalico.org/ipAddrs", logger)
	if err != nil {
		return nil, err
	}

	result := current.Result{}

	// Go through all the IPs passed in as annotation value and call IPAM plugin
	// for each, and populate the result variable with IP4 and/or IP6 IPs returned
	// from the IPAM plugin.
	for _, ip := range ipList {
		// Call callIPAMWithIP with the ip address.
		r, err := callIPAMWithIP(ip, conf, args, logger)
		if err != nil {
			return nil, fmt.Errorf("Error getting IP from IPAM: %s", err)
		}

		result.IPs = append(result.IPs, r.IPs[0])
		logger.Debugf("Adding IPv%s: %s to result", r.IPs[0].Version, ip.String())
	}

	return &result, nil
}

// callIPAMWithIP sets CNI_ARGS with the IP and calls the IPAM plugin with it
// to get current.Result and then it unsets the IP field from CNI_ARGS ENV var,
// so it doesn't pollute the subsequent requests.
func callIPAMWithIP(ip net.IP, conf utils.NetConf, args *skel.CmdArgs, logger *log.Entry) (*current.Result, error) {

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

	// Convert IPAM result into current Result.
	// IPAM result has a bunch of fields that are optional for an IPAM plugin
	// but required for a CNI plugin, so this is to populate those fields.
	// See CNI Spec doc for more details.
	ipamResult, err := current.NewResultFromResult(r)
	if err != nil {
		return nil, err
	}

	if len(ipamResult.IPs) == 0 {
		return nil, errors.New("IPAM plugin returned missing IP config")
	}

	return ipamResult, nil
}

// overrideIPAMResult generates current.Result like the one produced by IPAM plugin,
// but sets IP field manually since IPAM is bypassed with this annotation.
// Example annotation value string: "[\"10.0.0.1\", \"2001:db8::1\"]"
func overrideIPAMResult(ipAddrsNoIpam string, logger *log.Entry) (*current.Result, error) {
	logger.Infof("Parsing annotation \"cni.projectcalico.org/ipAddrsNoIpam\":%s", ipAddrsNoIpam)

	// We need to make sure there is only one IPv4 and/or one IPv6
	// passed in, since CNI spec only supports one of each right now.
	ipList, err := validateAndExtractIPs(ipAddrsNoIpam, "cni.projectcalico.org/ipAddrsNoIpam", logger)
	if err != nil {
		return nil, err
	}

	result := current.Result{}

	// Go through all the IPs passed in as annotation value and populate
	// the result variable with IP4 and/or IP6 IPs.
	for _, ip := range ipList {
		var version string
		var mask net.IPMask

		if ip.To4() != nil {
			version = "4"
			mask = net.CIDRMask(32, 32)

		} else {
			version = "6"
			mask = net.CIDRMask(128, 128)
		}

		ipConf := &current.IPConfig{
			Version: version,
			Address: net.IPNet{
				IP:   ip,
				Mask: mask,
			},
		}
		result.IPs = append(result.IPs, ipConf)
		logger.Debugf("Adding IPv%s: %s to result", ipConf.Version, ip.String())
	}

	return &result, nil
}

// validateAndExtractIPs is a utility function that validates the passed IP list to make sure
// there is one IPv4 and/or one IPv6 and then returns the slice of IPs.
func validateAndExtractIPs(ipAddrs string, annotation string, logger *log.Entry) ([]net.IP, error) {
	// Parse IPs from JSON.
	ips, err := parseIPAddrs(ipAddrs, logger)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse IPs %s for annotation \"%s\": %s", ipAddrs, annotation, err)
	}

	// annotation value can't be empty.
	if len(ips) == 0 {
		return nil, fmt.Errorf("Annotation \"%s\" specified but empty", annotation)
	}

	var hasIPv4, hasIPv6 bool
	var ipList []net.IP

	// We need to make sure there is only one IPv4 and/or one IPv6
	// passed in, since CNI spec only supports one of each right now.
	for _, ip := range ips {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			logger.WithField("IP", ip).Error("Invalid IP format")
			return nil, fmt.Errorf("Invalid IP format: %s", ip)
		}

		if ipAddr.To4() != nil {
			if hasIPv4 {
				// Check if there is already has been an IPv4 in the list, as we only support one IPv4 and/or one IPv6 per interface for now.
				return nil, fmt.Errorf("cannot have more than one IPv4 address for \"%s\" annotation", annotation)
			}
			hasIPv4 = true
		} else {
			if hasIPv6 {
				// Check if there is already has been an IPv6 in the list, as we only support one IPv4 and/or one IPv6 per interface for now.
				return nil, fmt.Errorf("cannot have more than one IPv6 address for \"%s\" annotation", annotation)
			}
			hasIPv6 = true
		}

		// Append the IP to ipList slice.
		ipList = append(ipList, ipAddr)
	}

	return ipList, nil
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

// releaseIPAddrs calls directly into Calico IPAM to release the specified IP addresses.
// NOTE: This function assumes Calico IPAM is in use, and calls into it directly rather than calling the IPAM plugin.
func releaseIPAddrs(ipAddrs []cnet.IPNet, calico *calicoclient.Client, logger *log.Entry) error {
	// For each IP, call out to Calico IPAM to release it.
	for _, ip := range ipAddrs {
		log := logger.WithField("IP", ip)
		log.Info("Releasing explicitly requested address")
		cip, _, err := cnet.ParseCIDR(ip.IP.String())
		if err != nil {
			return err
		}
		unallocated, err := calico.IPAM().ReleaseIPs([]cnet.IP{*cip})
		if err != nil {
			log.WithError(err).Error("Failed to release explicit IP")
			return err
		}
		if len(unallocated) > 0 {
			log.Warn("Asked to release address but it doesn't exist.")
		} else {
			log.Infof("Released explicit address: %s", ip)
		}
	}
	return nil
}
