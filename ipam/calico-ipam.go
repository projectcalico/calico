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

	log "github.com/Sirupsen/logrus"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/projectcalico/cni-plugin/utils"
	"github.com/projectcalico/libcalico-go/lib/client"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

// VERSION is filled out during the build process (using git describe output)
var VERSION string

func main() {

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

	skel.PluginMain(cmdAdd, cmdDel)
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

	r := &types.Result{}
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
			r.IP6 = &types.IPConfig{IP: ipNetwork}
			logger.WithField("result.IP6", r.IP6).Info("Result IPv6")
		} else {
			// It's an IPv4 address.
			ipNetwork = net.IPNet{IP: ipamArgs.IP, Mask: net.CIDRMask(32, 32)}
			r.IP4 = &types.IPConfig{IP: ipNetwork}
			logger.WithField("result.IP4", r.IP4).Info("Result IPv4")
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
			r.IP4 = &types.IPConfig{IP: ipV4Network}
		}

		if num6 == 1 {
			if len(assignedV6) != num6 {
				return fmt.Errorf("Failed to request %d IPv6 addresses. IPAM allocated only %d.", num6, len(assignedV6))
			}
			ipV6Network := net.IPNet{IP: assignedV6[0].IP, Mask: net.CIDRMask(128, 128)}
			r.IP6 = &types.IPConfig{IP: ipV6Network}
		}
		logger.WithFields(log.Fields{"result.IP4": r.IP4, "result.IP6": r.IP6}).Info("IPAM Result")
	}

	return r.Print()
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
		return err
	}

	logger.Info("Released address using workloadID")
	return nil

}
