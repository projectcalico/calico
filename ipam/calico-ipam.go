package main

import (
	"encoding/json"
	"fmt"
	"net"

	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/projectcalico/calico-cni/utils"
	"github.com/tigera/libcalico-go/lib/client"
	cnet "github.com/tigera/libcalico-go/lib/net"
)

func main() {
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

	if conf.Debug {
		utils.EnableDebugLogging()
	}

	calicoClient, err := utils.CreateClient(conf)
	if err != nil {
		return err
	}

	workloadID, _, err := utils.GetIdentifiers(args)
	if err != nil {
		return err
	}

	ipamArgs := ipamArgs{}
	if err = types.LoadArgs(args.Args, &ipamArgs); err != nil {
		return err
	}

	r := &types.Result{}
	if ipamArgs.IP != nil {
		fmt.Fprintf(os.Stderr, "Calico CNI IPAM request IP: %v\n", ipamArgs.IP)

		// The hostname will be defaulted to the actual hostname if cong.Hostname is empty
		assignArgs := client.AssignIPArgs{IP: cnet.IP{ipamArgs.IP}, HandleID: &workloadID, Hostname: conf.Hostname}
		err := calicoClient.IPAM().AssignIP(assignArgs)
		if err != nil {
			return err
		}

		ipV4Network := net.IPNet{IP: ipamArgs.IP, Mask: net.CIDRMask(32, 32)}
		r.IP4 = &types.IPConfig{IP: ipV4Network}
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

		assignArgs := client.AutoAssignArgs{Num4: num4, Num6: num6, HandleID: &args.ContainerID, Hostname: conf.Hostname}
		assignedV4, assignedV6, err := calicoClient.IPAM().AutoAssign(assignArgs)
		fmt.Fprintf(os.Stderr, "Calico CNI IPAM assigned addresses IPv4=%v IPv6=%v\n", assignedV4, assignedV6)
		if err != nil {
			return err
		}

		if num4 == 1 {
			ipV4Network := net.IPNet{IP: assignedV4[0].IP, Mask: net.CIDRMask(32, 32)}
			r.IP4 = &types.IPConfig{IP: ipV4Network}
		}

		if num6 == 1 {
			ipV6Network := net.IPNet{IP: assignedV6[0].IP, Mask: net.CIDRMask(128, 128)}
			r.IP6 = &types.IPConfig{IP: ipV6Network}
		}
	}

	return r.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	conf := utils.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if conf.Debug {
		utils.EnableDebugLogging()
	}

	calicoClient, err := utils.CreateClient(conf)
	if err != nil {
		return err
	}

	// Release the IP address by using the handle - which is workloadID.
	workloadID, _, err := utils.GetIdentifiers(args)
	if err != nil {
		return err
	}

	if err := calicoClient.IPAM().ReleaseByHandle(workloadID); err != nil {
		return err
	}

	return nil

}
