// Copyright (c) 2015-2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	cniSpecVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/mcuadros/go-version"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/libcalico-go/lib/seedrng"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/dataplane"
	"github.com/projectcalico/calico/cni-plugin/pkg/k8s"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const testConnectionTimeout = 2 * time.Second

func init() {
	// This ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func testConnection() error {
	// Unmarshal the network config
	conf := types.NetConf{}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return errors.New("failed to read from stdin")
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	// Create a new client.
	calicoClient, err := utils.CreateClient(conf)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), testConnectionTimeout)
	defer cancel()
	ci, err := calicoClient.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting ClusterInformation: %v", err)
	}
	if !*ci.Spec.DatastoreReady {
		logrus.Info("Upgrade may be in progress, ready flag is not set")
		return fmt.Errorf("Calico is currently not ready to process requests")
	}

	// If we have a kubeconfig, test connection to the APIServer
	if conf.Kubernetes.Kubeconfig != "" {
		k8sconfig, err := clientcmd.BuildConfigFromFlags("", conf.Kubernetes.Kubeconfig)
		if err != nil {
			return fmt.Errorf("error building K8s client config: %s", err)
		}

		// Set a short timeout so we fail fast.
		k8sconfig.Timeout = testConnectionTimeout
		k8sClient, err := kubernetes.NewForConfig(k8sconfig)
		if err != nil {
			return fmt.Errorf("error creating K8s client: %s", err)
		}
		_, err = k8sClient.ServerVersion()
		if err != nil {
			return fmt.Errorf("unable to connect to K8s server: %s", err)
		}
	}
	return nil
}

func isEndpointReady(readyEndpoint string, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, readyEndpoint, nil)
	if err != nil {
		return false, err
	}
	req = req.WithContext(ctx)
	resp, err := c.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false, fmt.Errorf("Endpoint is not ready, response code returned:%d", resp.StatusCode)
	}
	return true, nil
}

func pollEndpointReadiness(endpoint string, interval, timeout time.Duration) error {
	return wait.Poll(interval, timeout,
		func() (bool, error) {
			if isReady, err := isEndpointReady(endpoint, interval); !isReady {
				if err != nil {
					logrus.Errorf("Endpoint may not be ready:%v", err)
					return false, nil
				}
				logrus.Error("Endpoint not ready")
				return false, nil
			}
			return true, nil
		})
}

func cmdAdd(args *skel.CmdArgs) (err error) {
	// Defer a panic recover, so that in case we panic we can still return
	// a proper error to the runtime.
	defer func() {
		if e := recover(); e != nil {
			msg := fmt.Sprintf("Calico CNI panicked during ADD: %s\nStack trace:\n%s", e, string(debug.Stack()))
			if err != nil {
				// If we're recovering and there was also an error, then we need to
				// present both.
				msg = fmt.Sprintf("%s: error=%s", msg, err)
			}
			err = fmt.Errorf(msg)
		}
		if err != nil {
			logrus.WithError(err).Error("Final result of CNI ADD was an error.")
		}
	}()

	// Unmarshal the network config, and perform validation
	conf := types.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if len(conf.CNIVersion) < 1 {
		conf.CNIVersion = "0.2.0"
	}

	if version.Compare(conf.CNIVersion, "1.0.0", ">") {
		return fmt.Errorf("unsupported CNI version %s", conf.CNIVersion)
	}

	utils.ConfigureLogging(conf)

	nodeNameFile := "/var/lib/calico/nodename"
	if conf.NodenameFile != "" {
		nodeNameFile = conf.NodenameFile
	}

	if !conf.NodenameFileOptional {
		// Configured to wait for the nodename file - don't start until it exists.
		if _, err := os.Stat(nodeNameFile); err != nil {
			s := "%s: check that the calico/node container is running and has mounted /var/lib/calico/"
			return fmt.Errorf(s, err)
		}
		logrus.Debug("/var/lib/calico/nodename exists")
	}

	// Determine MTU to use.
	if mtu, err := utils.MTUFromFile("/var/lib/calico/mtu"); err != nil {
		return fmt.Errorf("failed to read MTU file: %s", err)
	} else if conf.MTU == 0 && mtu != 0 {
		// No MTU specified in config, but an MTU file was found on disk.
		// Use the value from the file.
		logrus.WithField("mtu", mtu).Debug("Using MTU from /var/lib/calico/mtu")
		conf.MTU = mtu
	}
	if conf.NumQueues <= 0 {
		conf.NumQueues = 1
	}

	// Determine which node name to use.
	nodename := utils.DetermineNodename(conf)

	// Extract WEP identifiers such as pod name, pod namespace (for k8s), containerID, IfName.
	wepIDs, err := utils.GetIdentifiers(args, nodename)
	if err != nil {
		return
	}

	logrus.WithField("EndpointIDs", wepIDs).Debug("Extracted identifiers")

	calicoClient, err := utils.CreateClient(conf)
	if err != nil {
		err = fmt.Errorf("error creating calico client: %v", err)
		return
	}

	ctx := context.Background()
	ci, err := calicoClient.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		err = fmt.Errorf("error getting ClusterInformation: %v", err)
		return
	}
	if !*ci.Spec.DatastoreReady {
		logrus.Info("Upgrade may be in progress, ready flag is not set")
		err = fmt.Errorf("Calico is currently not ready to process requests")
		return
	}

	for _, endpoint := range conf.ReadinessGates {
		if _, err := url.ParseRequestURI(endpoint); err != nil {
			return fmt.Errorf("Invalid URL set for ReadinessGates:%s Error:%v",
				endpoint, err)
		}
		err := pollEndpointReadiness(endpoint, 5*time.Second, 30*time.Second)
		if err != nil {
			return err
		}
	}

	// Remove the endpoint field (IfName) from the wepIDs so we can get a WEP name prefix.
	// We use the WEP name prefix (e.g. prefix: "node1-k8s-mypod--1-", full name: "node1-k8s-mypod--1-eth0"
	// to list all the WEPs so if we have a WEP with a different IfName (e.g. "node1-k8s-mypod--1-eth1")
	// we could still get that.
	wepIDs.Endpoint = ""

	// Calculate the workload name prefix from the WEP specific identifiers
	// for the given orchestrator.
	wepPrefix, err := wepIDs.CalculateWorkloadEndpointName(true)
	if err != nil {
		err = fmt.Errorf("error constructing WorkloadEndpoint prefix: %s", err)
		return
	}

	// Check if there's an existing endpoint by listing the existing endpoints based on the WEP name prefix.
	endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{Name: wepPrefix, Namespace: wepIDs.Namespace, Prefix: true})
	if err != nil {
		return
	}

	var logger *logrus.Entry
	if wepIDs.Orchestrator == api.OrchestratorKubernetes {
		logger = logrus.WithFields(logrus.Fields{
			"WorkloadEndpoint": fmt.Sprintf("%s%s", wepPrefix, wepIDs.Endpoint),
			"ContainerID":      wepIDs.ContainerID,
			"Pod":              wepIDs.Pod,
			"Namespace":        wepIDs.Namespace,
		})
	} else {
		logger = logrus.WithFields(logrus.Fields{
			"ContainerID": wepIDs.ContainerID,
		})
	}

	logger.Debugf("Retrieved list of endpoints: %v", endpoints)

	var endpoint *libapi.WorkloadEndpoint

	// If the prefix list returns 1 or more items, we go through the items and try to see if the name matches the WEP
	// identifiers we have. The identifiers we use for this match at this point are:
	// 1. Node name
	// 2. Orchestrator ID ('cni' or 'k8s')
	// 3. ContainerID
	// 4. Pod name (only for k8s)
	// Note we don't use the interface name (endpoint) for this match.
	// If we find a match from the returned list then we've found the workload endpoint,
	// and we reuse that even if it has a different interface name, because
	// we only support one interface per pod right now.
	// For example, you have a WEP for a k8s pod "mypod-1", and IfName "eth0" on node "node1", that will result in
	// a WEP name "node1-k8s-mypod--1-eth0" in the datastore, now you're trying to schedule another pod "mypod",
	// IfName "eth0" and node "node1", so we do a prefix list to get all the endpoints for that workload, with
	// the prefix "node1-k8s-mypod-". Now this search would return any existing endpoints for "mypod", but it will also
	// list "node1-k8s-mypod--1-eth0" which is not the same WorkloadEndpoint, so to avoid that, we go through the
	// list of returned WEPs from the prefix list and call NameMatches() based on all the
	// identifiers (pod name, containerID, node name, orchestrator), but omit the IfName (Endpoint field) since we can
	// only have one interface per pod right now, and NameMatches() will return true if the WEP matches the identifiers.
	// It is possible that none of the WEPs in the list match the identifiers, which means we don't already have an
	// existing WEP to reuse. See `names.WorkloadEndpointIdentifiers` GoDoc comments for more details.
	if len(endpoints.Items) > 0 {
		logger.Debugf("List of WorkloadEndpoints %v", endpoints.Items)
		for _, ep := range endpoints.Items {
			var match bool
			match, err = wepIDs.WorkloadEndpointIdentifiers.NameMatches(ep.Name)
			if err != nil {
				// We should never hit this error, because it should have already been
				// caught by CalculateWorkloadEndpointName.
				err = fmt.Errorf("invalid WorkloadEndpoint identifiers: %v", wepIDs.WorkloadEndpointIdentifiers)
				return
			}

			if match {
				logger.Debugf("Found a match for WorkloadEndpoint: %v", ep)
				endpoint = &ep
				// Assign the WEP name to wepIDs' WEPName field.
				wepIDs.WEPName = endpoint.Name
				// Put the endpoint name from the matched WEP in the identifiers.
				wepIDs.Endpoint = ep.Spec.Endpoint
				logger.Infof("Calico CNI found existing endpoint: %v", endpoint)
				break
			}
		}
	}

	// If we don't find a match from the existing WorkloadEndpoints then we calculate
	// the WEP name with the IfName passed in so we can create the WorkloadEndpoint later in the process.
	if endpoint == nil {
		wepIDs.Endpoint = args.IfName
		wepIDs.WEPName, err = wepIDs.CalculateWorkloadEndpointName(false)
		if err != nil {
			err = fmt.Errorf("error constructing WorkloadEndpoint name: %s", err)
			return
		}
	}

	// Collect the result in this variable - this is ultimately what gets "returned" by this function by printing
	// it to stdout.
	var result *cniv1.Result

	// If running under Kubernetes then branch off into the kubernetes code, otherwise handle everything in this
	// function.
	if wepIDs.Orchestrator == api.OrchestratorKubernetes {
		if result, err = k8s.CmdAddK8s(ctx, args, conf, *wepIDs, calicoClient, endpoint); err != nil {
			return
		}
	} else {
		// Default CNI behavior
		// Validate enabled features
		if conf.FeatureControl.IPAddrsNoIpam {
			err = errors.New("requested feature is not supported for this runtime: ip_addrs_no_ipam")
			return
		}

		// use the CNI network name as the Calico profile.
		profileID := conf.Name

		endpointAlreadyExisted := endpoint != nil
		if endpointAlreadyExisted {
			// There is an existing endpoint - no need to create another.
			// This occurs when adding an existing container to a new CNI network
			// Find the IP address from the endpoint and use that in the response.
			// Don't create the veth or do any networking.
			// Just update the profile on the endpoint. The profile will be created if needed during the
			// profile processing step.
			foundProfile := false
			for _, p := range endpoint.Spec.Profiles {
				if p == profileID {
					logger.Infof("Calico CNI endpoint already has profile: %s\n", profileID)
					foundProfile = true
					break
				}
			}
			if !foundProfile {
				logger.Infof("Calico CNI appending profile: %s\n", profileID)
				endpoint.Spec.Profiles = append(endpoint.Spec.Profiles, profileID)
			}
			result, err = utils.CreateResultFromEndpoint(endpoint)
			logger.WithField("result", result).Debug("Created result from endpoint")
			if err != nil {
				return
			}
		} else {
			// There's no existing endpoint, so we need to do the following:
			// 1) Call the configured IPAM plugin to get IP address(es)
			// 2) Configure the Calico endpoint
			// 3) Create the veth, configuring it on both the host and container namespace.

			// 1) Run the IPAM plugin and make sure there's an IP address returned.
			logger.WithFields(logrus.Fields{"paths": os.Getenv("CNI_PATH"),
				"type": conf.IPAM.Type}).Debug("Looking for IPAM plugin in paths")
			var ipamResult cnitypes.Result
			ipamResult, err = ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
			logger.WithField("IPAM result", ipamResult).Info("Got result from IPAM plugin")
			if err != nil {
				return
			}

			// Convert IPAM result into current Result.
			// IPAM result has a bunch of fields that are optional for an IPAM plugin
			// but required for a CNI plugin, so this is to populate those fields.
			// See CNI Spec doc for more details.
			result, err = cniv1.NewResultFromResult(ipamResult)
			if err != nil {
				utils.ReleaseIPAllocation(logger, conf, args)
				return
			}

			if len(result.IPs) == 0 {
				utils.ReleaseIPAllocation(logger, conf, args)
				err = errors.New("IPAM plugin returned no IP addresses in result")
				return
			}

			// Parse endpoint labels passed in by Mesos, and store in a map.
			labels := map[string]string{}
			for _, label := range conf.Args.Mesos.NetworkInfo.Labels.Labels {
				// Sanitize mesos labels so that they pass the k8s label validation,
				// as mesos labels accept any unicode value.
				k := utils.SanitizeMesosLabel(label.Key)
				v := utils.SanitizeMesosLabel(label.Value)

				if label.Key == "projectcalico.org/namespace" {
					wepIDs.Namespace = v
				} else {
					labels[k] = v
				}
			}

			// 2) Create the endpoint object
			endpoint = libapi.NewWorkloadEndpoint()
			endpoint.Name = wepIDs.WEPName
			endpoint.Namespace = wepIDs.Namespace
			endpoint.Spec.Endpoint = wepIDs.Endpoint
			endpoint.Spec.Node = wepIDs.Node
			endpoint.Spec.Orchestrator = wepIDs.Orchestrator
			endpoint.Spec.ContainerID = wepIDs.ContainerID
			endpoint.Labels = labels
			endpoint.Spec.Profiles = []string{profileID}

			logger.WithField("endpoint", endpoint).Debug("Populated endpoint (without nets)")
			if err = utils.PopulateEndpointNets(endpoint, result); err != nil {
				// Cleanup IP allocation and return the error.
				utils.ReleaseIPAllocation(logger, conf, args)
				return
			}
			logger.WithField("endpoint", endpoint).Info("Populated endpoint (with nets)")

			logger.Infof("Calico CNI using IPs: %s", endpoint.Spec.IPNetworks)

			// 3) Set up the veth
			var d dataplane.Dataplane
			d, err = dataplane.GetDataplane(conf, logger)
			if err != nil {
				return
			}

			// Select the first 11 characters of the containerID for the host veth.
			var hostVethName, contVethMac string
			desiredVethName := "cali" + args.ContainerID[:utils.Min(11, len(args.ContainerID))]
			hostVethName, contVethMac, err = d.DoNetworking(
				ctx, calicoClient, args, result, desiredVethName, utils.DefaultRoutes, endpoint, map[string]string{})
			if err != nil {
				// Cleanup IP allocation and return the error.
				utils.ReleaseIPAllocation(logger, conf, args)
				return
			}

			logger.WithFields(logrus.Fields{
				"HostVethName":     hostVethName,
				"ContainerVethMac": contVethMac,
			}).Info("Networked namespace")

			endpoint.Spec.MAC = contVethMac
			endpoint.Spec.InterfaceName = hostVethName
		}

		// Write the endpoint object (either the newly created one, or the updated one with a new ProfileIDs).
		if _, err = utils.CreateOrUpdate(ctx, calicoClient, endpoint); err != nil {
			if !endpointAlreadyExisted {
				// Only clean up the IP allocation if this was a new endpoint.  Otherwise,
				// we'd release the IP that is already attached to the existing endpoint.
				utils.ReleaseIPAllocation(logger, conf, args)
			}
			return
		}

		logger.WithField("endpoint", endpoint).Info("Wrote endpoint to datastore")

		// Add the interface created above to the CNI result.
		result.Interfaces = append(result.Interfaces, &cniv1.Interface{
			Name: endpoint.Spec.InterfaceName},
		)
	}

	// Handle profile creation - this is only done if there isn't a specific policy handler.
	if conf.Policy.PolicyType == "" {
		logger.Debug("Handling profiles")
		// Start by checking if the profile already exists. If it already exists then there is no work to do.
		// The CNI plugin never updates a profile.
		exists := true
		_, err = calicoClient.Profiles().Get(ctx, conf.Name, options.GetOptions{})
		if err != nil {
			_, ok := err.(cerrors.ErrorResourceDoesNotExist)
			if ok {
				exists = false
			} else {
				// Cleanup IP allocation and return the error.
				utils.ReleaseIPAllocation(logger, conf, args)
				return
			}
		}

		if !exists {
			// The profile doesn't exist so needs to be created. The rules vary depending on whether k8s is being used.
			// Under k8s (without full policy support) the rule is permissive and allows all traffic.
			// Otherwise, incoming traffic is only allowed from profiles with the same tag.
			logger.Infof("Calico CNI creating profile: %s", conf.Name)
			var inboundRules []api.Rule
			if wepIDs.Orchestrator == api.OrchestratorKubernetes {
				inboundRules = []api.Rule{{Action: api.Allow}}
			} else {
				inboundRules = []api.Rule{{Action: api.Allow, Source: api.EntityRule{Selector: fmt.Sprintf("has(%s)", conf.Name)}}}
			}

			profile := &api.Profile{
				ObjectMeta: metav1.ObjectMeta{
					Name: conf.Name,
				},
				Spec: api.ProfileSpec{
					Egress:        []api.Rule{{Action: api.Allow}},
					Ingress:       inboundRules,
					LabelsToApply: map[string]string{conf.Name: ""},
				},
			}

			logger.WithField("profile", profile).Info("Creating profile")

			if _, err = calicoClient.Profiles().Create(ctx, profile, options.SetOptions{}); err != nil {
				// Cleanup IP allocation and return the error.
				utils.ReleaseIPAllocation(logger, conf, args)
				return
			}
		}
	}

	// Set Gateway to nil. Calico IPAM doesn't set it, but host-local does.
	// We modify IPs subnet received from the IPAM plugin (host-local),
	// so Gateway isn't valid anymore. It is also not used anywhere by Calico.
	for _, ip := range result.IPs {
		ip.Gateway = nil
	}

	// Print result to stdout, in the format defined by the requested cniVersion.
	err = cnitypes.PrintResult(result, conf.CNIVersion)
	return
}

func cmdDel(args *skel.CmdArgs) (err error) {
	// Defer a panic recover, so that in case we panic we can still return
	// a proper error to the runtime.
	defer func() {
		if e := recover(); e != nil {
			msg := fmt.Sprintf("Calico CNI panicked during DEL: %s\nStack trace:\n%s", e, string(debug.Stack()))
			if err != nil {
				// If we're recovering and there was also an error, then we need to
				// present both.
				msg = fmt.Sprintf("%s: error=%s", msg, err)
			}
			err = fmt.Errorf(msg)
		}
		if err != nil {
			logrus.WithError(err).Error("Final result of CNI DEL was an error.")
		}
	}()

	conf := types.NetConf{}
	if err = json.Unmarshal(args.StdinData, &conf); err != nil {
		err = fmt.Errorf("failed to load netconf: %v", err)
		return
	}

	utils.ConfigureLogging(conf)

	nodeNameFile := "/var/lib/calico/nodename"
	if conf.NodenameFile != "" {
		nodeNameFile = conf.NodenameFile
	}

	if !conf.NodenameFileOptional {
		// Configured to wait for the nodename file - don't start until it exists.
		if _, err = os.Stat(nodeNameFile); err != nil {
			s := "%s: check that the calico/node container is running and has mounted /var/lib/calico/"
			err = fmt.Errorf(s, err)
			return
		}
		logrus.Debug("/var/lib/calico/nodename exists")
	}

	// Determine which node name to use.
	nodename := utils.DetermineNodename(conf)

	var epIDs *utils.WEPIdentifiers
	epIDs, err = utils.GetIdentifiers(args, nodename)
	if err != nil {
		return
	}
	logger := logrus.WithFields(logrus.Fields{"ContainerID": epIDs.ContainerID})

	var calicoClient clientv3.Interface
	calicoClient, err = utils.CreateClient(conf)
	if err != nil {
		return
	}

	ctx := context.Background()
	var ci *api.ClusterInformation
	ci, err = calicoClient.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		err = fmt.Errorf("error getting ClusterInformation: %v", err)
		return
	}
	if !*ci.Spec.DatastoreReady {
		logrus.Info("Upgrade may be in progress, ready flag is not set")
		err = fmt.Errorf("Calico is currently not ready to process requests")
		return
	}

	// Calculate the WEP name so we can call DEL on the exact endpoint.
	epIDs.WEPName, err = epIDs.CalculateWorkloadEndpointName(false)
	if err != nil {
		err = fmt.Errorf("error constructing WorkloadEndpoint name: %s", err)
		return
	}

	logger.WithFields(logrus.Fields{
		"Orchestrator":     epIDs.Orchestrator,
		"Node":             epIDs.Node,
		"WorkloadEndpoint": epIDs.WEPName,
		"ContainerID":      epIDs.ContainerID,
	}).Debug("Extracted identifiers")

	// Handle k8s specific bits of handling the DEL.
	if epIDs.Orchestrator == api.OrchestratorKubernetes {
		err = k8s.CmdDelK8s(ctx, calicoClient, *epIDs, args, conf, logger)
		return
	}

	// Release the IP address by calling the configured IPAM plugin.
	ipamErr := utils.DeleteIPAM(conf, args, logger)

	// Delete the WorkloadEndpoint object from the datastore.
	if _, err = calicoClient.WorkloadEndpoints().Delete(ctx, epIDs.Namespace, epIDs.WEPName, options.DeleteOptions{}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			// Log and proceed with the clean up if WEP doesn't exist.
			logger.WithField("WorkloadEndpoint", epIDs.WEPName).Info("Endpoint object does not exist, no need to clean up.")
			err = nil
		} else {
			return
		}
	}

	// Clean up namespace by removing the interfaces.
	var d dataplane.Dataplane
	d, err = dataplane.GetDataplane(conf, logger)
	if err != nil {
		return
	}

	err = d.CleanUpNamespace(args)
	if err != nil {
		return
	}

	// Return the IPAM error if there was one. The IPAM error will be lost if there was also an error in cleaning up
	// the device or endpoint, but crucially, the user will know the overall operation failed.
	err = ipamErr
	return
}

func cmdDummyCheck(args *skel.CmdArgs) (err error) {
	fmt.Println("OK")
	return nil
}

func Main(version string) {
	// Make sure the RNG is seeded.
	seedrng.EnsureSeeded()

	// Set up logging formatting.
	logrus.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file/line no information.
	logrus.AddHook(&logutils.ContextHook{})

	// Use a new flag set so as not to conflict with existing libraries which use "flag"
	flagSet := flag.NewFlagSet("Calico", flag.ExitOnError)

	// Display the version on "-v"
	versionFlag := flagSet.Bool("v", false, "Display version")

	// Test datastore connection on "-t" this is used to gate installation of the
	// CNI config file, which triggers some orchestrators (K8s included) to start
	// scheduling pods.  By waiting until we get a successful datastore connection
	// test, we can avoid some startup races where host networking to the datastore
	// takes a little while to start up.
	testConnectionFlag := flagSet.Bool("t", false, "Test datastore connection")

	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		cniError := cnitypes.Error{
			Code:    100,
			Msg:     "failed to parse CLI flags",
			Details: err.Error(),
		}
		cniError.Print()
		os.Exit(1)
	}
	if *versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}
	if *testConnectionFlag {
		err = testConnection()
		if err == nil {
			os.Exit(0)
		}
		logrus.WithError(err).Error("data store connection failed")
		cniError := cnitypes.Error{
			Code:    100,
			Msg:     "data store connection failed",
			Details: err.Error(),
		}
		cniError.Print()
		os.Exit(1)
	}

	if err := utils.AddIgnoreUnknownArgs(); err != nil {
		logrus.WithError(err).Error("Failed to set IgnoreUnknown=1")
		cniError := cnitypes.Error{
			Code:    100,
			Msg:     "failed to set IgnoreUnknown=1",
			Details: err.Error(),
		}
		cniError.Print()
		os.Exit(1)
	}

	skel.PluginMain(cmdAdd, cmdDummyCheck, cmdDel,
		cniSpecVersion.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "1.0.0"),
		"Calico CNI plugin "+version)
}
