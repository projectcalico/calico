package k8s

import (
	"fmt"
	"net"
	"strings"

	"os"

	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/projectcalico/calico-cni/utils"
	"github.com/projectcalico/libcalico-go/lib/api"
	cnet "github.com/projectcalico/libcalico-go/lib/net"

	"encoding/json"

	"k8s.io/client-go/1.4/kubernetes"
	"k8s.io/client-go/1.4/tools/clientcmd"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/client"
)

// CmdAddK8s performs the "ADD" operation on a kubernetes pod
// Having kubernetes code in its own file avoids polluting the mainline code. It's expected that the kubernetes case will
// more special casing than the mainline code.
func CmdAddK8s(args *skel.CmdArgs, conf utils.NetConf, hostname string, calicoClient *client.Client, endpoint *api.WorkloadEndpoint) (*types.Result, error) {
	var err error
	var result *types.Result

	k8sArgs := utils.K8sArgs{}
	err = types.LoadArgs(args.Args, &k8sArgs)
	if err != nil {
		return nil, err
	}

	utils.ConfigureLogging(conf.LogLevel)

	workloadID, orchestratorID, err := utils.GetIdentifiers(args)
	if err != nil {
		return nil, err
	}
	logger := utils.CreateContextLogger(workloadID)
	logger.WithFields(log.Fields{
		"OrchestratorID": orchestratorID,
		"Hostname":       hostname,
	}).Info("Extracted identifiers")

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
			podCidr, err := getPodCidr(client, conf, hostname)
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

		// Run the IPAM plugin
		result, err = ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
		if err != nil {
			return nil, err
		}

		// Create the endpoint object and configure it
		endpoint = api.NewWorkloadEndpoint()
		endpoint.Metadata.Name = args.IfName
		endpoint.Metadata.Hostname = hostname
		endpoint.Metadata.OrchestratorID = orchestratorID
		endpoint.Metadata.WorkloadID = workloadID
		endpoint.Metadata.Labels = make(map[string]string)

		// Set the profileID according to whether Kubernetes policy is required. If it's not, then just use the network
		// name (which is the normal behavior) otherwise use one based on the Kubernetes pod's Mamespace.

		if conf.Policy.PolicyType == "k8s" {
			endpoint.Spec.Profiles = []string{fmt.Sprintf("k8s_ns.%s", k8sArgs.K8S_POD_NAMESPACE)}
		} else {
			endpoint.Spec.Profiles = []string{conf.Name}
		}

		if err = utils.PopulateEndpointNets(endpoint, result); err != nil {
			// Cleanup IP allocation and return the error.
			utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
			return nil, err
		}
		logger.WithField("endpoint", endpoint).Info("Populated endpoint")

		// Only attempt to fetch the labels from Kubernetes if the policy type has been set to "k8s"
		// This allows users to run the plugin under Kubernetes without needing it to access the Kubernetes API
		if conf.Policy.PolicyType == "k8s" {
			labels, err := getK8sLabels(client, k8sArgs)
			if err != nil {
				// Cleanup IP allocation and return the error.
				utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
				return nil, err
			}
			logger.WithField("labels", labels).Info("Fetched K8s labels")
			endpoint.Metadata.Labels = labels
		}

		fmt.Fprintf(os.Stderr, "Calico CNI using IPs: %s\n", endpoint.Spec.IPNetworks)
	}

	// Whether the endpoint existed or not, the veth needs (re)creating.
	hostVethName, contVethMac, err := utils.DoNetworking(args, conf, result, logger)
	if err != nil {
		// Cleanup IP allocation and return the error.
		utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
		return nil, err
	}

	mac, err := net.ParseMAC(contVethMac)
	if err != nil {
		// Cleanup IP allocation and return the error.
		utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
		return nil, err
	}
	endpoint.Spec.MAC = cnet.MAC{HardwareAddr: mac}
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

func getK8sLabels(client *kubernetes.Clientset, k8sargs utils.K8sArgs) (map[string]string, error) {
	pods, err := client.Pods(string(k8sargs.K8S_POD_NAMESPACE)).Get(fmt.Sprintf("%s", k8sargs.K8S_POD_NAME))
	if err != nil {
		return nil, err
	}

	labels := pods.Labels
	if labels == nil {
		labels = make(map[string]string)
	}

	labels["calico/k8s_ns"] = fmt.Sprintf("%s", k8sargs.K8S_POD_NAMESPACE)

	return labels, nil
}

func getPodCidr(client *kubernetes.Clientset, conf utils.NetConf, hostname string) (string, error) {
	// Pull the node name out of the config if it's set. Defaults to hostname
	nodeName := hostname
	if conf.Kubernetes.NodeName != "" {
		nodeName = conf.Kubernetes.NodeName
	}

	node, err := client.Nodes().Get(nodeName)
	if err != nil {
		return "", err
	}

	if node.Spec.PodCIDR == "" {
		err = fmt.Errorf("No podCidr for node %s", nodeName)
		return "", err
	} else {
		return node.Spec.PodCIDR, nil
	}
}
