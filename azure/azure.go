package azure

import (
	"encoding/json"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/sirupsen/logrus"
)

// MutateConfigAdd mutates the provided configuration such that it will be accepted by the
// azure-vnet-ipam plugin. If the provided network contains a subnet, it will update the
// configuration to pass that subnet to the IPAM plugin.
func MutateConfigAdd(args *skel.CmdArgs, network AzureNetwork) error {
	if len(network.Subnets) == 0 {
		logrus.Info("No Azure subnets defined - don't mutate config (add)")
		return nil
	}
	var stdinData map[string]interface{}
	var err error
	if err = json.Unmarshal(args.StdinData, &stdinData); err != nil {
		return err
	}

	// For now, we only support a single subnet. The data model supports multiple though.
	stdinData["ipam"].(map[string]interface{})["subnet"] = network.Subnets[0]

	// Pack it back into the provided args.
	args.StdinData, err = json.Marshal(stdinData)
	if err != nil {
		return err
	}
	logrus.Infof("Updated CNI network configuration for Azure Add: %#v", stdinData)
	return nil
}

// MutateConfigDel mutates the provided configuration such that it will be accepted by the
// azure-vnet-ipam plugin on a delete operation. It populates the config with the address
// and subnet information in the provided network and endpoint.
func MutateConfigDel(args *skel.CmdArgs, network AzureNetwork, endpoint AzureEndpoint) error {
	if len(endpoint.Addresses) == 0 {
		logrus.Info("No addresses defined - don't mutate config (delete)")
		return nil
	}
	if len(network.Subnets) == 0 {
		logrus.Info("No Azure subnets defined - don't mutate config (delete)")
		return nil
	}

	var stdinData map[string]interface{}
	var err error
	if err = json.Unmarshal(args.StdinData, &stdinData); err != nil {
		return err
	}

	// For now, we only support a single address. The data model supports multiple though.
	// The azure-vnet-ipam plugin is not receptive to CIDR notation, so strip the prefix length
	// if it is present.
	splits := strings.Split(endpoint.Addresses[0], "/")
	stdinData["ipam"].(map[string]interface{})["ipAddress"] = splits[0]

	// For now, we only support a single subnet. The data model supports multiple though.
	stdinData["ipam"].(map[string]interface{})["subnet"] = network.Subnets[0]

	// Pack it back into the provided args.
	args.StdinData, err = json.Marshal(stdinData)
	if err != nil {
		return err
	}
	logrus.Infof("Updated CNI network configuration for Azure Del: %#v", stdinData)
	return nil
}
