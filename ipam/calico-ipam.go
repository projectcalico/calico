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
	"net"

	"os"

	log "github.com/sirupsen/logrus"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	cniSpecVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/projectcalico/cni-plugin/utils"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

// VERSION is filled out during the build process (using git describe output)
var VERSION string

func main() {
	// Set up logging formatting.
	log.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file/line no information.
	log.AddHook(&logutils.ContextHook{})

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
	types.CommonArgs
	IP net.IP `json:"ip,omitempty"`
}

func cmdAdd(args *skel.CmdArgs) error {
	conf := utils.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	cniVersion := conf.CNIVersion

	utils.ConfigureLogging(conf.LogLevel)

	calicoClient, err := utils.CreateClient(conf)
	if err != nil {
		return err
	}

	workloadID, _, err := utils.GetIdentifiers(args)
	if err != nil {
		return err
	}
	logger := utils.CreateContextLogger(workloadID)

	ipamArgs := ipamArgs{}
	if err = types.LoadArgs(args.Args, &ipamArgs); err != nil {
		return err
	}

	r := &current.Result{}
	if ipamArgs.IP != nil {
		fmt.Fprintf(os.Stderr, "Calico CNI IPAM request IP: %v\n", ipamArgs.IP)

		// The hostname will be defaulted to the actual hostname if conf.Hostname is empty
		assignArgs := client.AssignIPArgs{IP: cnet.IP{ipamArgs.IP}, HandleID: &workloadID, Hostname: conf.Hostname}
		logger.WithField("assignArgs", assignArgs).Info("Assigning provided IP")
		err := calicoClient.IPAM().AssignIP(assignArgs)
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

		v4pools, err := utils.ParsePools(conf.IPAM.IPv4Pools, true)
		if err != nil {
			return err
		}

		v6pools, err := utils.ParsePools(conf.IPAM.IPv6Pools, false)
		if err != nil {
			return err
		}

		assignArgs := client.AutoAssignArgs{
			Num4:      num4,
			Num6:      num6,
			HandleID:  &workloadID,
			Hostname:  conf.Hostname,
			IPv4Pools: v4pools,
			IPv6Pools: v6pools,
		}
		logger.WithField("assignArgs", assignArgs).Info("Auto assigning IP")
		assignedV4, assignedV6, err := calicoClient.IPAM().AutoAssign(assignArgs)
		fmt.Fprintf(os.Stderr, "Calico CNI IPAM assigned addresses IPv4=%v IPv6=%v\n", assignedV4, assignedV6)
		if err != nil {
			return err
		}

		if num4 == 1 {
			if len(assignedV4) != num4 {
				return fmt.Errorf("Failed to request %d IPv4 addresses. IPAM allocated only %d.", num4, len(assignedV4))
			}
			ipV4Network := net.IPNet{IP: assignedV4[0].IP, Mask: net.CIDRMask(32, 32)}
			r.IPs = append(r.IPs, &current.IPConfig{
				Version: "4",
				Address: ipV4Network,
			})
		}

		if num6 == 1 {
			if len(assignedV6) != num6 {
				return fmt.Errorf("Failed to request %d IPv6 addresses. IPAM allocated only %d.", num6, len(assignedV6))
			}
			ipV6Network := net.IPNet{IP: assignedV6[0].IP, Mask: net.CIDRMask(128, 128)}
			r.IPs = append(r.IPs, &current.IPConfig{
				Version: "6",
				Address: ipV6Network,
			})
		}
		logger.WithFields(log.Fields{"result.IPs": r.IPs}).Info("IPAM Result")
	}

	// Print result to stdout, in the format defined by the requested cniVersion.
	return types.PrintResult(r, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf := utils.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	utils.ConfigureLogging(conf.LogLevel)

	calicoClient, err := utils.CreateClient(conf)
	if err != nil {
		return err
	}

	// Release the IP address by using the handle - which is workloadID.
	workloadID, _, err := utils.GetIdentifiers(args)
	if err != nil {
		return err
	}

	logger := utils.CreateContextLogger(workloadID)

	logger.Info("Releasing address using workloadID")
	if err := calicoClient.IPAM().ReleaseByHandle(workloadID); err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
			logger.WithField("workloadId", workloadID).Warn("Asked to release address but it doesn't exist. Ignoring")
			return nil
		}
		return err
	}

	logger.Info("Released address using workloadID")
	return nil

}
