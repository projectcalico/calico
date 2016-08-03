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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/vishvananda/netlink"

	"net"

	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/projectcalico/calico-cni/k8s"
	. "github.com/projectcalico/calico-cni/utils"
	"github.com/satori/go.uuid"
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/errors"
	cnet "github.com/tigera/libcalico-go/lib/net"
)

var hostname string

func init() {
	// This ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()

	hostname, _ = os.Hostname()
}

func cmdAdd(args *skel.CmdArgs) error {
	// Unmarshall the network config, and perform validation
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if conf.Debug {
		EnableDebugLogging()
	}

	workloadID, orchestratorID, err := GetIdentifiers(args)
	if err != nil {
		return err
	}

	// Allow the hostname to be overridden by the network config
	if conf.Hostname != "" {
		hostname = conf.Hostname
	}
	calicoClient, err := CreateClient(conf)
	if err != nil {
		return err
	}
	// Always check if there's an existing endpoint.
	endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{
		Hostname:       hostname,
		OrchestratorID: orchestratorID,
		WorkloadID:     workloadID})
	if err != nil {
		return err
	}
	var endpoint *api.WorkloadEndpoint
	if len(endpoints.Items) == 1 {
		endpoint = &endpoints.Items[0]
	}

	fmt.Fprintf(os.Stderr, "Calico CNI checking for existing endpoint: %v\n", endpoint)

	// Collect the result in this variable - this is ultimately what gets "returned" by this function by printing
	// it to stdout.
	var result *types.Result

	// If running under Kubernetes then branch off into the kubernetes code, otherwise handle everything in this
	// function.
	if orchestratorID == "k8s" {
		if result, err = k8s.CmdAddK8s(args, conf, hostname, calicoClient, endpoint); err != nil {
			return err
		}
	} else {
		// Default CNI behavior - use the CNI network name as the Calico profile.
		profileID := conf.Name

		if endpoint != nil {
			// There is an existing endpoint - no need to create another.
			// This occurs when adding an existing container to a new CNI network
			// Find the IP address from the endpoint and use that in the response.
			// Don't create the veth or do any networking.
			// Just update the profile on the endpoint. The profile will be created if needed during the
			// profile processing step.
			fmt.Fprintf(os.Stderr, "Calico CNI appending profile: %s\n", profileID)
			endpoint.Spec.Profiles = append(endpoint.Spec.Profiles, profileID)
			result, err = CreateResultFromEndpoint(endpoint)
			if err != nil {
				return err
			}
		} else {
			// There's no existing endpoint, so we need to do the following:
			// 1) Call the configured IPAM plugin to get IP address(es)
			// 2) Configure the Calico endpoint
			// 3) Create the veth, configuring it on both the host and container namespace.

			// 1) Run the IPAM plugin and make sure there's an IP address returned.
			result, err = ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
			if err != nil {
				return err
			}

			// 2) Create the endpoint object
			endpoint = api.NewWorkloadEndpoint()
			endpoint.Metadata.Hostname = hostname
			endpoint.Metadata.OrchestratorID = orchestratorID
			endpoint.Metadata.WorkloadID = workloadID
			endpoint.Metadata.Name = fmt.Sprintf("%x", uuid.NewV1())
			endpoint.Spec.Profiles = []string{profileID}

			if err = PopulateEndpointNets(endpoint, result); err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "Calico CNI using IPs: %s\n", endpoint.Spec.IPNetworks)

			// 3) Set up the veth
			hostVethName, contVethMac, err := DoNetworking(args, conf, result)
			if err != nil {
				return err
			}

			mac, err := net.ParseMAC(contVethMac)
			if err != nil {
				return err
			}

			endpoint.Spec.MAC = cnet.MAC{HardwareAddr: mac}
			endpoint.Spec.InterfaceName = hostVethName
		}

		// Write the endpoint object (either the newly created one, or the updated one with a new ProfileIDs).
		if _, err := calicoClient.WorkloadEndpoints().Apply(endpoint); err != nil {
			return err
		}
	}

	// Handle profile creation - this is only done if there isn't a specific policy handler.
	if conf.Policy.PolicyType == "" {
		// Start by checking if the profile already exists. If it already exists then there is no work to do.
		// The CNI plugin never updates a profile.
		exists := true
		_, err = calicoClient.Profiles().Get(api.ProfileMetadata{Name: conf.Name})
		if err != nil {
			_, ok := err.(errors.ErrorResourceDoesNotExist)
			if ok {
				exists = false
			} else {
				return err
			}
		}

		if !exists {
			// The profile doesn't exist so needs to be created. The rules vary depending on whether k8s is being used.
			// Under k8s (without full policy support) the rule is permissive and allows all traffic.
			// Otherwise, incoming traffic is only allowed from profiles with the same tag.
			fmt.Fprintf(os.Stderr, "Calico CNI creating profile: %s\n", conf.Name)
			var inboundRules []api.Rule
			if orchestratorID == "k8s" {
				inboundRules = []api.Rule{{Action: "allow"}}
			} else {
				inboundRules = []api.Rule{{Action: "allow", Source: api.EntityRule{Tag: conf.Name}}}
			}

			profile := api.NewProfile()
			profile.Metadata.Name = conf.Name
			profile.Spec.Tags = []string{conf.Name}
			profile.Spec.EgressRules = []api.Rule{{Action: "allow"}}
			profile.Spec.IngressRules = inboundRules

			if _, err := calicoClient.Profiles().Create(profile); err != nil {
				return err
			}
		}
	}

	return result.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if conf.Debug {
		EnableDebugLogging()
	}

	// Always try to release the address. Don't deal with any errors till the endpoints are cleaned up.
	ipamErr := ipam.ExecDel(conf.IPAM.Type, args.StdinData)

	// Always try to clean up the workload/endpoint.
	workloadID, orchestratorID, err := GetIdentifiers(args)
	if err != nil {
		return err
	}

	// Allow the hostname to be overridden by the network config
	if conf.Hostname != "" {
		hostname = conf.Hostname
	}

	calicoClient, err := CreateClient(conf)
	if err != nil {
		return err
	}

	if err := calicoClient.WorkloadEndpoints().Delete(api.WorkloadEndpointMetadata{
		Hostname:       hostname,
		OrchestratorID: orchestratorID,
		WorkloadID:     workloadID}); err != nil {
		return err
	}

	// Only try to delete the device if a namespace was passed in.
	if args.Netns != "" {
		err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
			_, err = ip.DelLinkByNameAddr(args.IfName, netlink.FAMILY_V4)
			return err
		})

		if err != nil {
			return err
		}
	}

	// Return the IPAM error if there was one. The IPAM error will be lost if there was also an error in cleaning up
	// the device or endpoint, but crucially, the user will know the overall operation failed.
	return ipamErr
}

// VERSION is filled out during the build process (using git describe output)
var VERSION string

func main() {
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

	if err := AddIgnoreUnknownArgs(); err != nil {
		os.Exit(1)
	}

	skel.PluginMain(cmdAdd, cmdDel)
}
