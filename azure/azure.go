package azure

import (
	"encoding/json"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/sirupsen/logrus"
)

// TODO:
func MutateConfigAdd(args *skel.CmdArgs, network AzureNetwork) error {
	if len(network.Subnets) == 0 {
		logrus.Info("No Azure subnets defined - don't mutate config")
		return nil
	}
	var stdinData map[string]interface{}
	var err error
	if err = json.Unmarshal(args.StdinData, &stdinData); err != nil {
		return err
	}
	stdinData["ipam"].(map[string]interface{})["subnet"] = network.Subnets[0]

	// Pack it back into the provided args.
	args.StdinData, err = json.Marshal(stdinData)
	if err != nil {
		return err
	}
	logrus.Infof("Updated CNI network configuration for Azure: %#v", stdinData)
	return nil
}

// TODO:
func MutateConfigDel(args *skel.CmdArgs, endpoint AzureEndpoint) error {
	if len(endpoint.Addresses) == 0 {
		logrus.Info("No addresses defined - don't mutate config")
		return nil
	}

	var stdinData map[string]interface{}
	var err error
	if err = json.Unmarshal(args.StdinData, &stdinData); err != nil {
		return err
	}
	stdinData["ipam"].(map[string]interface{})["address"] = endpoint.Addresses[0]

	// Pack it back into the provided args.
	args.StdinData, err = json.Marshal(stdinData)
	if err != nil {
		return err
	}
	logrus.Infof("Updated CNI network configuration for Azure: %#v", stdinData)
	return nil
}
