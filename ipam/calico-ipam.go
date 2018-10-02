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
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	cniSpecVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/projectcalico/cni-plugin/types"
	"github.com/projectcalico/cni-plugin/utils"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/sirupsen/logrus"
)

// VERSION is filled out during the build process (using git describe output)
var VERSION string

func main() {
	// Set up logging formatting.
	logrus.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file/line no information.
	logrus.AddHook(&logutils.ContextHook{})

	// Display the version on "-v", otherwise just delegate to the skel code.
	// Use a new flag set so as not to conflict with existing libraries which use "flag"
	flagSet := flag.NewFlagSet("calico-ipam", flag.ExitOnError)

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

	skel.PluginMain(cmdAdd, cmdDel, cniSpecVersion.All)
}

type ipamArgs struct {
	cnitypes.CommonArgs
	IP net.IP `json:"ip,omitempty"`
}

func cmdAdd(args *skel.CmdArgs) error {
	conf := types.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	nodename := utils.DetermineNodename(conf)

	utils.ConfigureLogging(conf.LogLevel)

	calicoClient, err := utils.CreateClient(conf)
	if err != nil {
		return err
	}

	epIDs, err := utils.GetIdentifiers(args, nodename)
	if err != nil {
		return err
	}

	epIDs.WEPName, err = epIDs.CalculateWorkloadEndpointName(false)
	if err != nil {
		return fmt.Errorf("error constructing WorkloadEndpoint name: %s", err)
	}

	handleID, err := utils.GetHandleID(conf.Name, args.ContainerID, epIDs.WEPName)
	if err != nil {
		return err
	}

	logger := logrus.WithFields(logrus.Fields{
		"Workload":    epIDs.WEPName,
		"ContainerID": epIDs.ContainerID,
		"HandleID":    handleID,
	})

	ipamArgs := ipamArgs{}
	if err = cnitypes.LoadArgs(args.Args, &ipamArgs); err != nil {
		return err
	}

	ctx := context.Background()
	r := &current.Result{}
	if ipamArgs.IP != nil {
		fmt.Fprintf(os.Stderr, "Calico CNI IPAM request IP: %v\n", ipamArgs.IP)

		// The hostname will be defaulted to the actual hostname if conf.Nodename is empty
		assignArgs := ipam.AssignIPArgs{
			IP:       cnet.IP{IP: ipamArgs.IP},
			HandleID: &handleID,
			Hostname: nodename,
		}

		logger.WithField("assignArgs", assignArgs).Info("Assigning provided IP")
		err := calicoClient.IPAM().AssignIP(ctx, assignArgs)
		if err != nil {
			return err
		}

		var ipNetwork net.IPNet

		if ipamArgs.IP.To4() == nil {
			// It's an IPv6 address.
			ipNetwork = net.IPNet{IP: ipamArgs.IP, Mask: net.CIDRMask(128, 128)}
			r.IPs = append(r.IPs, &current.IPConfig{
				Version: "6",
				Address: ipNetwork,
			})

			logger.WithField("result.IPs", ipamArgs.IP).Info("Appending an IPv6 address to the result")
		} else {
			// It's an IPv4 address.
			ipNetwork = net.IPNet{IP: ipamArgs.IP, Mask: net.CIDRMask(32, 32)}
			r.IPs = append(r.IPs, &current.IPConfig{
				Version: "4",
				Address: ipNetwork,
			})

			logger.WithField("result.IPs", ipamArgs.IP).Info("Appending an IPv4 address to the result")
		}
	} else {
		// Default to assigning an IPv4 address
		num4 := 1
		if conf.IPAM.AssignIpv4 != nil && *conf.IPAM.AssignIpv4 == "false" {
			num4 = 0
		}

		// Default to NOT assigning an IPv6 address
		num6 := 0
		if conf.IPAM.AssignIpv6 != nil && *conf.IPAM.AssignIpv6 == "true" {
			num6 = 1
		}

		fmt.Fprintf(os.Stderr, "Calico CNI IPAM request count IPv4=%d IPv6=%d\n", num4, num6)

		v4pools, err := utils.ResolvePools(ctx, calicoClient, conf.IPAM.IPv4Pools, true)
		if err != nil {
			return err
		}

		v6pools, err := utils.ResolvePools(ctx, calicoClient, conf.IPAM.IPv6Pools, false)
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "Calico CNI IPAM handle=%s\n", handleID)
		assignArgs := ipam.AutoAssignArgs{
			Num4:      num4,
			Num6:      num6,
			HandleID:  &handleID,
			Hostname:  nodename,
			IPv4Pools: v4pools,
			IPv6Pools: v6pools,
		}
		logger.WithField("assignArgs", assignArgs).Info("Auto assigning IP")
		assignedV4, assignedV6, err := calicoClient.IPAM().AutoAssign(ctx, assignArgs)
		fmt.Fprintf(os.Stderr, "Calico CNI IPAM assigned addresses IPv4=%v IPv6=%v\n", assignedV4, assignedV6)
		if err != nil {
			return err
		}

		if num4 == 1 {
			if len(assignedV4) != num4 {
				return fmt.Errorf("failed to request %d IPv4 addresses. IPAM allocated only %d", num4, len(assignedV4))
			}
			ipV4Network := net.IPNet{IP: assignedV4[0].IP, Mask: net.CIDRMask(32, 32)}
			r.IPs = append(r.IPs, &current.IPConfig{
				Version: "4",
				Address: ipV4Network,
			})
		}

		if num6 == 1 {
			if len(assignedV6) != num6 {
				return fmt.Errorf("failed to request %d IPv6 addresses. IPAM allocated only %d", num6, len(assignedV6))
			}
			ipV6Network := net.IPNet{IP: assignedV6[0].IP, Mask: net.CIDRMask(128, 128)}
			r.IPs = append(r.IPs, &current.IPConfig{
				Version: "6",
				Address: ipV6Network,
			})
		}
		logger.WithFields(logrus.Fields{"result.IPs": r.IPs}).Info("IPAM Result")
	}

	// Print result to stdout, in the format defined by the requested cniVersion.
	return cnitypes.PrintResult(r, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf := types.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	utils.ConfigureLogging(conf.LogLevel)

	calicoClient, err := utils.CreateClient(conf)
	if err != nil {
		return err
	}

	nodename := utils.DetermineNodename(conf)

	// Release the IP address by using the handle - which is workloadID.
	epIDs, err := utils.GetIdentifiers(args, nodename)
	if err != nil {
		return err
	}

	epIDs.WEPName, err = epIDs.CalculateWorkloadEndpointName(false)
	if err != nil {
		return fmt.Errorf("error constructing WorkloadEndpoint name: %s", err)
	}

	handleID, err := utils.GetHandleID(conf.Name, args.ContainerID, epIDs.WEPName)
	if err != nil {
		return err
	}

	logger := logrus.WithFields(logrus.Fields{
		"Workload":    epIDs.WEPName,
		"ContainerID": epIDs.ContainerID,
		"HandleID":    handleID,
	})

	logger.Info("Releasing address using handleID")
	ctx := context.Background()
	if err := calicoClient.IPAM().ReleaseByHandle(ctx, handleID); err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			logger.WithError(err).Error("Failed to release address")
			return err
		}
		logger.Warn("Asked to release address but it doesn't exist. Ignoring")
	} else {
		logger.Info("Released address using handleID")
	}

	// Calculate the workloadID to account for v2.x upgrades.
	workloadID := epIDs.ContainerID
	if epIDs.Orchestrator == "k8s" {
		workloadID = fmt.Sprintf("%s.%s", epIDs.Namespace, epIDs.Pod)
	}

	logger.Info("Releasing address using workloadID")
	if err := calicoClient.IPAM().ReleaseByHandle(ctx, workloadID); err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			logger.WithError(err).Error("Failed to release address")
			return err
		}
		logger.WithField("workloadID", workloadID).Debug("Asked to release address but it doesn't exist. Ignoring")
	} else {
		logger.WithField("workloadID", workloadID).Info("Released address using workloadID")
	}

	return nil
}
