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
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	cniSpecVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/projectcalico/cni-plugin/k8s"
	"github.com/projectcalico/cni-plugin/types"
	"github.com/projectcalico/cni-plugin/utils"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	// This ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func cmdAdd(args *skel.CmdArgs) error {
	// Unmarshal the network config, and perform validation
	conf := types.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	utils.ConfigureLogging(conf.LogLevel)

	if !conf.NodenameFileOptional {
		// Configured to wait for the nodename file - don't start until it exists.
		if _, err := os.Stat("/var/lib/calico/nodename"); err != nil {
			s := "%s: check that the calico/node container is running and has mounted /var/lib/calico/"
			return fmt.Errorf(s, err)
		}
		logrus.Debug("/var/lib/calico/nodename exists")
	}

	// Determine which node name to use.
	nodename := utils.DetermineNodename(conf)

	// Extract WEP identifiers such as pod name, pod namespace (for k8s), containerID, IfName.
	wepIDs, err := utils.GetIdentifiers(args, nodename)
	if err != nil {
		return err
	}

	logrus.WithField("EndpointIDs", wepIDs).Info("Extracted identifiers")

	calicoClient, err := utils.CreateClient(conf)
	if err != nil {
		return err
	}

	ctx := context.Background()
	ci, err := calicoClient.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting ClusterInformation: %v", err)
	}
	if *ci.Spec.DatastoreReady != true {
		logrus.Info("Upgrade may be in progress, ready flag is not set")
		return fmt.Errorf("Calico is currently not ready to process requests")
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
		return fmt.Errorf("error constructing WorkloadEndpoint prefix: %s", err)
	}

	// Check if there's an existing endpoint by listing the existing endpoints based on the WEP name prefix.
	endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{Name: wepPrefix, Namespace: wepIDs.Namespace, Prefix: true})
	if err != nil {
		return err
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

	var endpoint *api.WorkloadEndpoint

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
			match, err := wepIDs.WorkloadEndpointIdentifiers.NameMatches(ep.Name)
			if err != nil {
				// We should never hit this error, because it should have already been
				// caught by CalculateWorkloadEndpointName.
				return fmt.Errorf("invalid WorkloadEndpoint identifiers: %v", wepIDs.WorkloadEndpointIdentifiers)
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
			return fmt.Errorf("error constructing WorkloadEndpoint name: %s", err)
		}
	}

	// Collect the result in this variable - this is ultimately what gets "returned" by this function by printing
	// it to stdout.
	var result *current.Result

	// If running under Kubernetes then branch off into the kubernetes code, otherwise handle everything in this
	// function.
	if wepIDs.Orchestrator == api.OrchestratorKubernetes {
		if result, err = k8s.CmdAddK8s(ctx, args, conf, *wepIDs, calicoClient, endpoint); err != nil {
			return err
		}
	} else {
		// Default CNI behavior
		// Validate enabled features
		if conf.FeatureControl.IPAddrsNoIpam {
			return errors.New("requested feature is not supported for this runtime: ip_addrs_no_ipam")
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
				return err
			}
		} else {
			// There's no existing endpoint, so we need to do the following:
			// 1) Call the configured IPAM plugin to get IP address(es)
			// 2) Configure the Calico endpoint
			// 3) Create the veth, configuring it on both the host and container namespace.

			// 1) Run the IPAM plugin and make sure there's an IP address returned.
			logger.WithFields(logrus.Fields{"paths": os.Getenv("CNI_PATH"),
				"type": conf.IPAM.Type}).Debug("Looking for IPAM plugin in paths")
			ipamResult, err := ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
			logger.WithField("IPAM result", ipamResult).Info("Got result from IPAM plugin")
			if err != nil {
				return err
			}

			// Convert IPAM result into current Result.
			// IPAM result has a bunch of fields that are optional for an IPAM plugin
			// but required for a CNI plugin, so this is to populate those fields.
			// See CNI Spec doc for more details.
			result, err = current.NewResultFromResult(ipamResult)
			if err != nil {
				utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
				return err
			}

			if len(result.IPs) == 0 {
				utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
				return errors.New("IPAM plugin returned missing IP config")
			}

			// Parse endpoint labels passed in by Mesos, and store in a map.
			labels := map[string]string{}
			for _, label := range conf.Args.Mesos.NetworkInfo.Labels.Labels {
				// Sanitize mesos labels so that they pass the k8s label validation,
				// as mesos labels accept any unicode value.
				k := utils.SanitizeMesosLabel(label.Key)
				v := utils.SanitizeMesosLabel(label.Value)

				labels[k] = v
			}

			// 2) Create the endpoint object
			endpoint = api.NewWorkloadEndpoint()
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
				utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
				return err
			}
			logger.WithField("endpoint", endpoint).Info("Populated endpoint (with nets)")

			fmt.Fprintf(os.Stderr, "Calico CNI using IPs: %s\n", endpoint.Spec.IPNetworks)

			// 3) Set up the veth
			hostVethName, contVethMac, err := utils.DoNetworking(
				args, conf, result, logger, "", utils.DefaultRoutes)
			if err != nil {
				// Cleanup IP allocation and return the error.
				utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
				return err
			}

			logger.WithFields(logrus.Fields{
				"HostVethName":     hostVethName,
				"ContainerVethMac": contVethMac,
			}).Info("Networked namespace")

			endpoint.Spec.MAC = contVethMac
			endpoint.Spec.InterfaceName = hostVethName
		}

		// Write the endpoint object (either the newly created one, or the updated one with a new ProfileIDs).
		if _, err := utils.CreateOrUpdate(ctx, calicoClient, endpoint); err != nil {
			if !endpointAlreadyExisted {
				// Only clean up the IP allocation if this was a new endpoint.  Otherwise,
				// we'd release the IP that is already attached to the existing endpoint.
				utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
			}
			return err
		}

		logger.WithField("endpoint", endpoint).Info("Wrote endpoint to datastore")

		// Add the interface created above to the CNI result.
		result.Interfaces = append(result.Interfaces, &current.Interface{
			Name: endpoint.Spec.InterfaceName, Sandbox: endpoint.Spec.Endpoint},
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
				utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
				return err
			}
		}

		if !exists {
			// The profile doesn't exist so needs to be created. The rules vary depending on whether k8s is being used.
			// Under k8s (without full policy support) the rule is permissive and allows all traffic.
			// Otherwise, incoming traffic is only allowed from profiles with the same tag.
			fmt.Fprintf(os.Stderr, "Calico CNI creating profile: %s\n", conf.Name)
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

			if _, err := calicoClient.Profiles().Create(ctx, profile, options.SetOptions{}); err != nil {
				// Cleanup IP allocation and return the error.
				utils.ReleaseIPAllocation(logger, conf.IPAM.Type, args.StdinData)
				return err
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
	return cnitypes.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf := types.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	utils.ConfigureLogging(conf.LogLevel)

	if !conf.NodenameFileOptional {
		// Configured to wait for the nodename file - don't start until it exists.
		if _, err := os.Stat("/var/lib/calico/nodename"); err != nil {
			s := "%s: check that the calico/node container is running and has mounted /var/lib/calico/"
			return fmt.Errorf(s, err)
		}
		logrus.Debug("/var/lib/calico/nodename exists")
	}

	// Determine which node name to use.
	nodename := utils.DetermineNodename(conf)

	epIDs, err := utils.GetIdentifiers(args, nodename)
	if err != nil {
		return err
	}

	logger := logrus.WithFields(logrus.Fields{
		"ContainerID": epIDs.ContainerID,
	})

	calicoClient, err := utils.CreateClient(conf)
	if err != nil {
		return err
	}

	ctx := context.Background()
	ci, err := calicoClient.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting ClusterInformation: %v", err)
	}
	if *ci.Spec.DatastoreReady != true {
		logrus.Info("Upgrade may be in progress, ready flag is not set")
		return fmt.Errorf("Calico is currently not ready to process requests")
	}

	// Calculate the WEP name so we can call DEL on the exact endpoint.
	epIDs.WEPName, err = epIDs.CalculateWorkloadEndpointName(false)
	if err != nil {
		return fmt.Errorf("error constructing WorkloadEndpoint name: %s", err)
	}

	logger.WithFields(logrus.Fields{
		"Orchestrator":     epIDs.Orchestrator,
		"Node":             epIDs.Node,
		"WorkloadEndpoint": epIDs.WEPName,
		"ContainerID":      epIDs.ContainerID,
	}).Info("Extracted identifiers")

	// Handle k8s specific bits of handling the DEL.
	if epIDs.Orchestrator == api.OrchestratorKubernetes {
		return k8s.CmdDelK8s(ctx, calicoClient, *epIDs, args, conf, logger)
	}

	// Release the IP address by calling the configured IPAM plugin.
	ipamErr := utils.CleanUpIPAM(conf, args, logger)

	// Delete the WorkloadEndpoint object from the datastore.
	if _, err = calicoClient.WorkloadEndpoints().Delete(ctx, epIDs.Namespace, epIDs.WEPName, options.DeleteOptions{}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			// Log and proceed with the clean up if WEP doesn't exist.
			logger.WithField("WorkloadEndpoint", epIDs.WEPName).Info("Endpoint object does not exist, no need to clean up.")
		} else {
			return err
		}
	}

	// Clean up namespace by removing the interfaces.
	err = utils.CleanUpNamespace(args, logger)
	if err != nil {
		return err
	}

	// Return the IPAM error if there was one. The IPAM error will be lost if there was also an error in cleaning up
	// the device or endpoint, but crucially, the user will know the overall operation failed.
	return ipamErr
}

// VERSION is filled out during the build process (using git describe output)
var VERSION string

func main() {
	// Set up logging formatting.
	logrus.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file/line no information.
	logrus.AddHook(&logutils.ContextHook{})

	// Display the version on "-v", otherwise just delegate to the skel code.
	// Use a new flag set so as not to conflict with existing libraries which use "flag"
	flagSet := flag.NewFlagSet("Calico", flag.ExitOnError)

	version := flagSet.Bool("v", false, "Display version")
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if *version {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	if err := utils.AddIgnoreUnknownArgs(); err != nil {
		os.Exit(1)
	}

	skel.PluginMain(cmdAdd, cmdDel, cniSpecVersion.All)
}
