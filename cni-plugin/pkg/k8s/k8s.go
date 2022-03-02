// Copyright (c) 2015-2021 Tigera, Inc. All rights reserved.
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ipam"

	libipam "github.com/projectcalico/calico/libcalico-go/lib/ipam"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	k8sconversion "github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	calicoclient "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils/cri"
	"github.com/projectcalico/calico/cni-plugin/pkg/dataplane"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
)

// CmdAddK8s performs the "ADD" operation on a kubernetes pod
// Having kubernetes code in its own file avoids polluting the mainline code. It's expected that the kubernetes case will
// more special casing than the mainline code.
func CmdAddK8s(ctx context.Context, args *skel.CmdArgs, conf types.NetConf, epIDs utils.WEPIdentifiers, calicoClient calicoclient.Interface, endpoint *libapi.WorkloadEndpoint) (*current.Result, error) {
	var err error
	var result *current.Result

	utils.ConfigureLogging(conf)

	logger := logrus.WithFields(logrus.Fields{
		"WorkloadEndpoint": epIDs.WEPName,
		"ContainerID":      epIDs.ContainerID,
		"Pod":              epIDs.Pod,
		"Namespace":        epIDs.Namespace,
	})

	d, err := dataplane.GetDataplane(conf, logger)
	if err != nil {
		return nil, err
	}

	logger.Info("Extracted identifiers for CmdAddK8s")

	result, err = utils.CheckForSpuriousDockerAdd(args, conf, epIDs, endpoint, logger)
	if result != nil || err != nil {
		return result, err
	}

	// Allocate the IP and update/create the endpoint. Do this even if the endpoint already exists and has an IP
	// allocation. The kubelet will send a DEL call for any old containers and we'll clean up the old IPs then.
	client, err := NewK8sClient(conf, logger)
	if err != nil {
		return nil, err
	}
	logger.WithField("client", client).Debug("Created Kubernetes client")

	var routes []*net.IPNet
	if conf.IPAM.Type == "host-local" {
		// We're using the host-local IPAM plugin.  We implement some special-case support for that
		// plugin.  Namely:
		//
		// - We support a special value for its subnet config field, "usePodCIDR".  If that is specified,
		//   we swap the string "usePodCIDR" for the actual PodCIDR (looked up via the k8s API) before we pass the
		//   configuration to the plugin.
		// - We have partial support for its "routes" setting, which allows the routes that we install into
		//   the pod to be varied from our default (which is to insert /0 routes via the host).  If any routes
		//   are specified in the routes section then only the specified routes are programmed.  Since Calico
		//   uses a point-to-point link, the gateway parameter of the route is ignored and the host side IP
		//   of the veth is used instead.
		//
		// We unpack the JSON data as an untyped map rather than using a typed struct because we want to
		// round-trip any fields that we don't know about.
		var stdinData map[string]interface{}
		if err := json.Unmarshal(args.StdinData, &stdinData); err != nil {
			return nil, err
		}

		// Defer to ReplaceHostLocalIPAMPodCIDRs to swap the "usePodCidr" value out.
		var cachedPodCidrs []string
		var cachedIpv4Cidr, cachedIpv6Cidr string
		getRealPodCIDRs := func() (string, string, error) {
			if len(cachedPodCidrs) == 0 {
				var err error
				var emptyResult string
				cachedPodCidrs, err = getPodCidrs(client, conf, epIDs.Node)
				if err != nil {
					return emptyResult, emptyResult, err
				}
				cachedIpv4Cidr, cachedIpv6Cidr, err = getIPsByFamily(cachedPodCidrs)
				if err != nil {
					return emptyResult, emptyResult, err
				}
			}
			return cachedIpv4Cidr, cachedIpv6Cidr, nil
		}
		err = utils.ReplaceHostLocalIPAMPodCIDRs(logger, stdinData, getRealPodCIDRs)
		if err != nil {
			return nil, err
		}

		// Write any changes we made back to the input data so that it'll be passed on to the IPAM plugin.
		args.StdinData, err = json.Marshal(stdinData)
		if err != nil {
			return nil, err
		}
		logger.Debug("Updated stdin data")

		// Extract any custom routes from the IPAM configuration.
		ipamData := stdinData["ipam"].(map[string]interface{})
		untypedRoutes := ipamData["routes"]
		hlRoutes, ok := untypedRoutes.([]interface{})
		if untypedRoutes != nil && !ok {
			return nil, fmt.Errorf(
				"failed to parse host-local IPAM routes section; expecting list, not: %v", stdinData["ipam"])
		}
		for _, route := range hlRoutes {
			route := route.(map[string]interface{})
			untypedDst, ok := route["dst"]
			if !ok {
				logger.Debug("Ignoring host-ipam route with no dst")
				continue
			}
			dst, ok := untypedDst.(string)
			if !ok {
				return nil, fmt.Errorf(
					"invalid IPAM routes section; expecting 'dst' to be a string, not: %v", untypedDst)
			}
			_, cidr, err := net.ParseCIDR(dst)
			if err != nil {
				logger.WithError(err).WithField("routeDest", dst).Error(
					"Failed to parse destination of host-local IPAM route in CNI configuration.")
				return nil, err
			}
			routes = append(routes, cidr)
		}
	}

	// Determine which routes to program within the container. If no routes were provided in the CNI config,
	// then use the Calico default routes. If routes were provided then program those instead.
	if len(routes) == 0 {
		logger.Debug("No routes specified in CNI configuration, using defaults.")
		routes = utils.DefaultRoutes
	} else {
		if conf.IncludeDefaultRoutes {
			// We're configured to also include our own default route, so do that here.
			logger.Debug("Including Calico default routes in addition to routes from CNI config")
			routes = append(utils.DefaultRoutes, routes...)
		}
		logger.WithField("routes", routes).Info("Using custom routes from CNI configuration.")
	}

	labels := make(map[string]string)
	annot := make(map[string]string)

	var ports []libapi.WorkloadEndpointPort
	var profiles []string
	var generateName string
	var serviceAccount string

	// Only attempt to fetch the labels and annotations from Kubernetes
	// if the policy type has been set to "k8s". This allows users to
	// run the plugin under Kubernetes without needing it to access the
	// Kubernetes API
	if conf.Policy.PolicyType == "k8s" {
		annotNS, err := getK8sNSInfo(client, epIDs.Namespace)
		if err != nil {
			return nil, err
		}
		logger.WithField("NS Annotations", annotNS).Debug("Fetched K8s namespace annotations")

		labels, annot, ports, profiles, generateName, serviceAccount, err = getK8sPodInfo(client, epIDs.Pod, epIDs.Namespace)
		if err != nil {
			return nil, err
		}
		logger.WithField("labels", labels).Debug("Fetched K8s labels")
		logger.WithField("annotations", annot).Debug("Fetched K8s annotations")
		logger.WithField("ports", ports).Debug("Fetched K8s ports")
		logger.WithField("profiles", profiles).Debug("Generated profiles")

		// Check for calico IPAM specific annotations and set them if needed.
		if conf.IPAM.Type == "calico-ipam" {

			var v4pools, v6pools string

			// Sets  the Namespace annotation for IP pools as default
			v4pools = annotNS["cni.projectcalico.org/ipv4pools"]
			v6pools = annotNS["cni.projectcalico.org/ipv6pools"]

			// Gets the POD annotation for IP Pools and overwrites Namespace annotation if it exists
			v4poolpod := annot["cni.projectcalico.org/ipv4pools"]
			if len(v4poolpod) != 0 {
				v4pools = v4poolpod
			}
			v6poolpod := annot["cni.projectcalico.org/ipv6pools"]
			if len(v6poolpod) != 0 {
				v6pools = v6poolpod
			}

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
						return nil, errors.New("data on stdin was of unexpected type")
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
						return nil, errors.New("data on stdin was of unexpected type")
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
				logger.Debug("Updated stdin data")
			}
		}
	}

	ipAddrsNoIpam := annot["cni.projectcalico.org/ipAddrsNoIpam"]
	ipAddrs := annot["cni.projectcalico.org/ipAddrs"]

	// Switch based on which annotations are passed or not passed.
	switch {
	case ipAddrs == "" && ipAddrsNoIpam == "":
		// Call the IPAM plugin.
		result, err = utils.AddIPAM(conf, args, logger)
		if err != nil {
			return nil, err
		}

	case ipAddrs != "" && ipAddrsNoIpam != "":
		// Can't have both ipAddrs and ipAddrsNoIpam annotations at the same time.
		e := fmt.Errorf("can't have both annotations: 'ipAddrs' and 'ipAddrsNoIpam' in use at the same time")
		logger.Error(e)
		return nil, e

	case ipAddrsNoIpam != "":
		// Validate that we're allowed to use this feature.
		if conf.IPAM.Type != "calico-ipam" {
			e := fmt.Errorf("ipAddrsNoIpam is not compatible with configured IPAM: %s", conf.IPAM.Type)
			logger.Error(e)
			return nil, e
		}
		if !conf.FeatureControl.IPAddrsNoIpam {
			e := fmt.Errorf("requested feature is not enabled: ip_addrs_no_ipam")
			logger.Error(e)
			return nil, e
		}

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
			return nil, errors.New("failed to build result")
		}

	case ipAddrs != "":
		// Validate that we're allowed to use this feature.
		if conf.IPAM.Type != "calico-ipam" {
			e := fmt.Errorf("ipAddrs is not compatible with configured IPAM: %s", conf.IPAM.Type)
			logger.Error(e)
			return nil, e
		}

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

	// Configure the endpoint (creating if required).
	if endpoint == nil {
		logger.Debug("Initializing new WorkloadEndpoint resource")
		endpoint = libapi.NewWorkloadEndpoint()
	}
	endpoint.Name = epIDs.WEPName
	endpoint.Namespace = epIDs.Namespace
	endpoint.Labels = labels
	endpoint.GenerateName = generateName
	endpoint.Spec.Endpoint = epIDs.Endpoint
	endpoint.Spec.Node = epIDs.Node
	endpoint.Spec.Orchestrator = epIDs.Orchestrator
	endpoint.Spec.Pod = epIDs.Pod
	endpoint.Spec.Ports = ports
	endpoint.Spec.IPNetworks = []string{}
	endpoint.Spec.ServiceAccountName = serviceAccount

	// Set the profileID according to whether Kubernetes policy is required.
	// If it's not, then just use the network name (which is the normal behavior)
	// otherwise use one based on the Kubernetes pod's profile(s).
	if conf.Policy.PolicyType == "k8s" {
		endpoint.Spec.Profiles = profiles
	} else {
		endpoint.Spec.Profiles = []string{conf.Name}
	}

	// Populate the endpoint with the output from the IPAM plugin.
	if err = utils.PopulateEndpointNets(endpoint, result); err != nil {
		// Cleanup IP allocation and return the error.
		utils.ReleaseIPAllocation(logger, conf, args)
		return nil, err
	}
	logger.WithField("endpoint", endpoint).Info("Populated endpoint")
	logger.Infof("Calico CNI using IPs: %s", endpoint.Spec.IPNetworks)

	// releaseIPAM cleans up any IPAM allocations on failure.
	releaseIPAM := func() {
		logger.WithField("endpointIPs", endpoint.Spec.IPNetworks).Info("Releasing IPAM allocation(s) after failure")
		utils.ReleaseIPAllocation(logger, conf, args)
	}

	// Whether the endpoint existed or not, the veth needs (re)creating.
	desiredVethName := k8sconversion.NewConverter().VethNameForWorkload(epIDs.Namespace, epIDs.Pod)
	hostVethName, contVethMac, err := d.DoNetworking(
		ctx, calicoClient, args, result, desiredVethName, routes, endpoint, annot)
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
	endpoint.Spec.MAC = mac.String()
	endpoint.Spec.InterfaceName = hostVethName
	endpoint.Spec.ContainerID = epIDs.ContainerID
	logger.WithField("endpoint", endpoint).Info("Added Mac, interface name, and active container ID to endpoint")

	if conf.Mode == "vxlan" {
		_, subNet, _ := net.ParseCIDR(result.IPs[0].Address.String())
		var err error
		for attempts := 3; attempts > 0; attempts-- {
			err = utils.EnsureVXLANTunnelAddr(ctx, calicoClient, epIDs.Node, subNet, conf.Name)
			if err != nil {
				logger.WithError(err).Warn("Failed to set node's VXLAN tunnel IP, node may not receive traffic.  May retry...")
				time.Sleep(1 * time.Second)
				continue
			}
			break
		}
		if err != nil {
			logger.WithError(err).Error("Failed to set node's VXLAN tunnel IP after retries, node may not receive traffic.")
		}
	}

	// List of DNAT ipaddrs to map to this workload endpoint
	floatingIPs := annot["cni.projectcalico.org/floatingIPs"]

	if floatingIPs != "" {
		// If floating IPs are defined, but the feature is not enabled, return an error.
		if !conf.FeatureControl.FloatingIPs {
			releaseIPAM()
			return nil, fmt.Errorf("requested feature is not enabled: floating_ips")
		}
		ips, err := parseIPAddrs(floatingIPs, logger)
		if err != nil {
			releaseIPAM()
			return nil, err
		}

		// Get IPv4 and IPv6 targets for NAT
		var podnetV4, podnetV6 net.IPNet
		for _, ipNet := range result.IPs {
			if ipNet.Address.IP.To4() != nil {
				podnetV4 = ipNet.Address
				netmask, _ := podnetV4.Mask.Size()
				if netmask != 32 {
					return nil, fmt.Errorf("PodIP %v is not a valid IPv4: Mask size is %d, not 32", ipNet, netmask)
				}
			} else {
				podnetV6 = ipNet.Address
				netmask, _ := podnetV6.Mask.Size()
				if netmask != 128 {
					return nil, fmt.Errorf("PodIP %v is not a valid IPv6: Mask size is %d, not 128", ipNet, netmask)
				}
			}
		}

		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				endpoint.Spec.IPNATs = append(endpoint.Spec.IPNATs, libapi.IPNAT{
					InternalIP: podnetV6.IP.String(),
					ExternalIP: ip,
				})
			} else {
				endpoint.Spec.IPNATs = append(endpoint.Spec.IPNATs, libapi.IPNAT{
					InternalIP: podnetV4.IP.String(),
					ExternalIP: ip,
				})
			}
		}
		logger.WithField("endpoint", endpoint).Info("Added floatingIPs to endpoint")
	}

	// Write the endpoint object (either the newly created one, or the updated one)
	if _, err := utils.CreateOrUpdate(ctx, calicoClient, endpoint); err != nil {
		logger.WithError(err).Error("Error creating/updating endpoint in datastore.")
		releaseIPAM()
		return nil, err
	}
	logger.Info("Wrote updated endpoint to datastore")

	// Add the interface created above to the CNI result.
	result.Interfaces = append(result.Interfaces, &current.Interface{
		Name: endpoint.Spec.InterfaceName,
	},
	)

	return result, nil
}

// CmdDelK8s performs CNI DEL processing when running under Kubernetes. In Kubernetes, we identify workload endpoints based on their
// pod name and namespace rather than container ID, so we may receive multiple DEL calls for the same pod, but with different container IDs.
// As such, we must only delete the workload endpoint when the provided CNI_CONATAINERID matches the value on the WorkloadEndpoint. If they do not match,
// it means the DEL is for an old sandbox and the pod is still running. We should still clean up IPAM allocations, since they are identified by the
// container ID rather than the pod name and namespace. If they do match, then we can delete the workload endpoint.
func CmdDelK8s(ctx context.Context, c calicoclient.Interface, epIDs utils.WEPIdentifiers, args *skel.CmdArgs, conf types.NetConf, logger *logrus.Entry) error {
	d, err := dataplane.GetDataplane(conf, logger)
	if err != nil {
		return err
	}

	// We only use pod timestamps for dockershim.
	if cri.IsDockershimV1(args.Netns) {
		// Register timestamp before deleting wep. This is important.
		// Because with ADD command running in parallel checking wep before checking timestamp,
		// DEL command should run the process in reverse order to avoid race condition.
		err = utils.RegisterDeletedWep(args.ContainerID)
		if err != nil {
			logger.WithError(err).Warn("Failed to register pod deletion timestamp.")
			return err
		}
	}

	for attempts := 5; attempts >= 0; attempts-- {
		wep, err := c.WorkloadEndpoints().Get(ctx, epIDs.Namespace, epIDs.WEPName, options.GetOptions{})
		if err != nil {
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
				// Could not connect to datastore (connection refused, unauthorized, etc.)
				// so we have no way of knowing/checking ContainerID. To protect the endpoint
				// from false DEL, we return the error without deleting/cleaning up.
				return err
			}

			// The WorkloadEndpoint doesn't exist for some reason. We should still try to clean up any IPAM allocations
			// if they exist, so continue DEL processing.
			logger.WithField("WorkloadEndpoint", epIDs.WEPName).Warning("WorkloadEndpoint does not exist in the datastore, moving forward with the clean up")
		} else if wep.Spec.ContainerID != "" && args.ContainerID != wep.Spec.ContainerID {
			// If the ContainerID is populated and doesn't match the CNI_CONTAINERID provided for this execution, then
			// we shouldn't delete the workload endpoint. We identify workload endpoints based on pod name and namespace, which means
			// we can receive DEL commands for an old sandbox for a currently running pod. However, we key IPAM allocations based on the
			// CNI_CONTAINERID, so we should still do that below for this case.
			logger.WithField("WorkloadEndpoint", wep).Warning("CNI_CONTAINERID does not match WorkloadEndpoint ConainerID, don't delete WEP.")
		} else if _, err = c.WorkloadEndpoints().Delete(
			ctx,
			wep.Namespace,
			wep.Name,
			options.DeleteOptions{
				ResourceVersion: wep.ResourceVersion,
				UID:             &wep.UID,
			},
		); err != nil {
			// Delete the WorkloadEndpoint object from the datastore, passing revision information from the
			// queried resource above in order to prevent conflicts.
			switch err := err.(type) {
			case cerrors.ErrorResourceDoesNotExist:
				// Log and proceed with the clean up if WEP doesn't exist.
				logger.WithField("endpoint", wep).Info("Endpoint object does not exist, no need to clean up.")
			case cerrors.ErrorResourceUpdateConflict:
				// This case means the WEP object was modified between the time we did the Get and now, retry
				// a few times and then return the error.  kubelet should then retry the whole DEL later.
				if attempts == 0 {
					logger.WithField("endpoint", wep).Warn("Endpoint was modified before it could be deleted.  Giving up.")
					return fmt.Errorf("error deleting endpoint: endpoint was modified before it could be deleted: %v", err)
				}
				logger.WithField("endpoint", wep).Info("Endpoint was modified before it could be deleted.  Retrying...")
				continue
			case cerrors.ErrorOperationNotSupported:
				// Defensive: shouldn't be hittable any more since KDD now supports pod deletion.
				logger.WithField("endpoint", wep).WithError(err).Warn("Deleting pod returned ErrorOperationNotSupported.")
			default:
				return err
			}
		}
		break
	}

	// Clean up namespace by removing the interfaces.
	logger.Info("Cleaning up netns")
	err = d.CleanUpNamespace(args)
	if err != nil {
		return err
	}

	// Release the IP address for this container by calling the configured IPAM plugin.
	logger.Info("Releasing IP address(es)")
	err = utils.DeleteIPAM(conf, args, logger)
	if err != nil {
		return err
	}

	logger.Info("Teardown processing complete.")
	return nil
}

// releaseIPAddrs calls directly into Calico IPAM to release the specified IP addresses.
// NOTE: This function assumes Calico IPAM is in use, and calls into it directly rather than calling the IPAM plugin.
func releaseIPAddrs(ipAddrs []string, calico calicoclient.Interface, logger *logrus.Entry) error {
	// For each IP, call out to Calico IPAM to release it.
	for _, ip := range ipAddrs {
		log := logger.WithField("IP", ip)
		log.Info("Releasing explicitly requested address")
		cip, _, err := cnet.ParseCIDR(ip)
		if err != nil {
			return err
		}
		unallocated, err := calico.IPAM().ReleaseIPs(context.Background(), libipam.ReleaseOptions{Address: cip.String()})
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

// ipAddrsResult parses the ipAddrs annotation and calls the configured IPAM plugin for
// each IP passed to it by setting the IP field in CNI_ARGS, and returns the result of calling the IPAM plugin.
// Example annotation value string: "[\"10.0.0.1\", \"2001:db8::1\"]"
func ipAddrsResult(ipAddrs string, conf types.NetConf, args *skel.CmdArgs, logger *logrus.Entry) (*current.Result, error) {
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
			return nil, fmt.Errorf("error getting IP from IPAM: %s", err)
		}

		result.IPs = append(result.IPs, r.IPs[0])
		logger.Debugf("Adding IPv%s: %s to result", r.IPs[0].Version, ip.String())
	}

	return &result, nil
}

// callIPAMWithIP sets CNI_ARGS with the IP and calls the IPAM plugin with it
// to get current.Result and then it unsets the IP field from CNI_ARGS ENV var,
// so it doesn't pollute the subsequent requests.
func callIPAMWithIP(ip net.IP, conf types.NetConf, args *skel.CmdArgs, logger *logrus.Entry) (*current.Result, error) {
	// Save the original value of the CNI_ARGS ENV var for backup.
	originalArgs := os.Getenv("CNI_ARGS")
	logger.Debugf("Original CNI_ARGS=%s", originalArgs)

	ipamArgs := struct {
		cnitypes.CommonArgs
		IP net.IP `json:"ip,omitempty"`
	}{}

	if err := cnitypes.LoadArgs(args.Args, &ipamArgs); err != nil {
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
		return nil, fmt.Errorf("error setting CNI_ARGS environment variable: %v", err)
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
		utils.ReleaseIPAllocation(logger, conf, args)
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
func overrideIPAMResult(ipAddrsNoIpam string, logger *logrus.Entry) (*current.Result, error) {
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
func validateAndExtractIPs(ipAddrs string, annotation string, logger *logrus.Entry) ([]net.IP, error) {
	// Parse IPs from JSON.
	ips, err := parseIPAddrs(ipAddrs, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPs %s for annotation \"%s\": %s", ipAddrs, annotation, err)
	}

	// annotation value can't be empty.
	if len(ips) == 0 {
		return nil, fmt.Errorf("annotation \"%s\" specified but empty", annotation)
	}

	var hasIPv4, hasIPv6 bool
	var ipList []net.IP

	// We need to make sure there is only one IPv4 and/or one IPv6
	// passed in, since CNI spec only supports one of each right now.
	for _, ip := range ips {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			logger.WithField("IP", ip).Error("Invalid IP format")
			return nil, fmt.Errorf("invalid IP format: %s", ip)
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
func parseIPAddrs(ipAddrsStr string, logger *logrus.Entry) ([]string, error) {
	var ips []string

	err := json.Unmarshal([]byte(ipAddrsStr), &ips)
	if err != nil {
		return nil, fmt.Errorf("failed to parse '%s' as JSON: %s", ipAddrsStr, err)
	}

	logger.Debugf("IPs parsed: %v", ips)

	return ips, nil
}

func NewK8sClient(conf types.NetConf, logger *logrus.Entry) (*kubernetes.Clientset, error) {
	// Some config can be passed in a kubeconfig file
	kubeconfig := conf.Kubernetes.Kubeconfig

	// Config can be overridden by config passed in explicitly in the network config.
	configOverrides := &clientcmd.ConfigOverrides{}

	// If an API root is given, make sure we're using using the name / port rather than
	// the full URL. Earlier versions of the config required the full `/api/v1/` extension,
	// so split that off to ensure compatibility.
	conf.Policy.K8sAPIRoot = strings.Split(conf.Policy.K8sAPIRoot, "/api/")[0]

	overridesMap := []struct {
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

	// Create the clientset
	return kubernetes.NewForConfig(config)
}

func getK8sNSInfo(client *kubernetes.Clientset, podNamespace string) (annotations map[string]string, err error) {
	ns, err := client.CoreV1().Namespaces().Get(context.Background(), podNamespace, metav1.GetOptions{})
	logrus.Debugf("namespace info %+v", ns)
	if err != nil {
		return nil, err
	}
	return ns.Annotations, nil
}

func getK8sPodInfo(client *kubernetes.Clientset, podName, podNamespace string) (labels map[string]string, annotations map[string]string, ports []libapi.WorkloadEndpointPort, profiles []string, generateName, serviceAccount string, err error) {
	pod, err := client.CoreV1().Pods(string(podNamespace)).Get(context.Background(), podName, metav1.GetOptions{})
	logrus.Debugf("pod info %+v", pod)
	if err != nil {
		return nil, nil, nil, nil, "", "", err
	}

	c := k8sconversion.NewConverter()
	kvps, err := c.PodToWorkloadEndpoints(pod)
	if err != nil {
		return nil, nil, nil, nil, "", "", err
	}

	kvp := kvps[0]
	ports = kvp.Value.(*libapi.WorkloadEndpoint).Spec.Ports
	labels = kvp.Value.(*libapi.WorkloadEndpoint).Labels
	profiles = kvp.Value.(*libapi.WorkloadEndpoint).Spec.Profiles
	generateName = kvp.Value.(*libapi.WorkloadEndpoint).GenerateName
	serviceAccount = kvp.Value.(*libapi.WorkloadEndpoint).Spec.ServiceAccountName

	return labels, pod.Annotations, ports, profiles, generateName, serviceAccount, nil
}

// getPodCidrs returns the podCidrs included in the node manifest
func getPodCidrs(client *kubernetes.Clientset, conf types.NetConf, nodename string) ([]string, error) {
	var emptyString []string
	// Pull the node name out of the config if it's set. Defaults to nodename
	if conf.Kubernetes.NodeName != "" {
		nodename = conf.Kubernetes.NodeName
	}

	node, err := client.CoreV1().Nodes().Get(context.Background(), nodename, metav1.GetOptions{})
	if err != nil {
		return emptyString, err
	}
	if len(node.Spec.PodCIDRs) == 0 {
		return emptyString, fmt.Errorf("no podCidr for node %s", nodename)
	}
	return node.Spec.PodCIDRs, nil
}

// getIPsByFamily returns the IPv4 and IPv6 CIDRs
func getIPsByFamily(cidrs []string) (string, string, error) {
	var ipv4Cidr, ipv6Cidr string
	for _, cidr := range cidrs {
		_, ipNet, err := cnet.ParseCIDR(cidr)
		if err != nil {
			return "", "", err
		}
		if ipNet.Version() == 4 {
			ipv4Cidr = cidr
		}

		if ipNet.Version() == 6 {
			ipv6Cidr = cidr
		}
	}

	if (len(cidrs) > 1) && (ipv4Cidr == "" || ipv6Cidr == "") {
		return "", "", errors.New("ClusterCIDR contains two ranges of the same type")
	}

	return ipv4Cidr, ipv6Cidr, nil
}
