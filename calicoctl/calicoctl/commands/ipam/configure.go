// Copyright (c) 2016,2020 Tigera, Inc. All rights reserved.

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

package ipam

import (
	"context"
	"fmt"
	"strconv"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
)

func updateIPAMConfig(
	ctx context.Context,
	ipamClient ipam.Interface,
	strictAffinity *bool,
	maxBlocks *int,
	persistence *ipam.VMAddressPersistence,
	ipCooldownSeconds *int,
) error {
	ipamConfig, err := ipamClient.GetIPAMConfig(ctx)
	if err != nil {
		return fmt.Errorf("error: %v", err)
	}

	// Update StrictAffinity if specified.
	if strictAffinity != nil {
		ipamConfig.StrictAffinity = *strictAffinity
	}

	// Set MaxBlocksPerHost if specified.
	if maxBlocks != nil {
		ipamConfig.MaxBlocksPerHost = *maxBlocks
	}

	// Update KubeVirtVMAddressPersistence if specified.
	if persistence != nil {
		ipamConfig.KubeVirtVMAddressPersistence = persistence
	}

	// Update IPCooldownSeconds if specified.
	if ipCooldownSeconds != nil {
		ipamConfig.IPCooldownSeconds = *ipCooldownSeconds
	}

	err = ipamClient.SetIPAMConfig(ctx, *ipamConfig)
	if err != nil {
		return fmt.Errorf("error: %v", err)
	}

	if strictAffinity != nil {
		fmt.Println("Successfully set StrictAffinity to:", *strictAffinity)
	}
	if maxBlocks != nil {
		fmt.Println("Successfully set MaxBlocksPerHost to:", *maxBlocks)
	}
	if persistence != nil {
		fmt.Println("Successfully set KubeVirtVMAddressPersistence to:", *persistence)
	}
	if ipCooldownSeconds != nil {
		fmt.Println("Successfully set IPCooldownSeconds to:", *ipCooldownSeconds)
	}

	return nil
}

// parsePersistence validates and converts CLI value to typed enum.
func parsePersistence(val string) (*ipam.VMAddressPersistence, error) {
	switch val {
	case string(ipam.VMAddressPersistenceEnabled):
		p := ipam.VMAddressPersistenceEnabled
		return &p, nil
	case string(ipam.VMAddressPersistenceDisabled):
		p := ipam.VMAddressPersistenceDisabled
		return &p, nil
	default:
		return nil, fmt.Errorf("invalid value for --kubevirt-ip-persistence. Use Enabled or Disabled")
	}
}

// ConfigureIPAM updates IPAM configuration from pre-parsed flag values.
func ConfigureIPAM(ctx context.Context, config, strictAffinityStr, maxBlocksStr, persistenceStr string, ipCooldownSecondsInt int) error {
	client, err := clientmgr.NewClient(config)
	if err != nil {
		return err
	}

	ipamClient := client.IPAM()

	var strictAffinity *bool
	if strictAffinityStr != "" {
		enabled, err := strconv.ParseBool(strictAffinityStr)
		if err != nil {
			return fmt.Errorf("invalid value. Use true or false to set strictaffinity")
		}
		strictAffinity = &enabled
	}

	var maxBlocks *int
	if maxBlocksStr != "" {
		maxBlocksVal, err := strconv.Atoi(maxBlocksStr)
		if err != nil {
			return fmt.Errorf("invalid value for maxblockhost. Use a valid number")
		}
		maxBlocks = &maxBlocksVal
	}

	var persistence *ipam.VMAddressPersistence
	if persistenceStr != "" {
		persistence, err = parsePersistence(persistenceStr)
		if err != nil {
			return err
		}
	}

	var ipCooldownSeconds *int
	if ipCooldownSecondsInt >= 0 {
		ipCooldownSeconds = &ipCooldownSecondsInt
	}

	if strictAffinity == nil && maxBlocks == nil && persistence == nil && ipCooldownSeconds == nil {
		return fmt.Errorf("at least one configuration option must be specified")
	}

	return updateIPAMConfig(ctx, ipamClient, strictAffinity, maxBlocks, persistence, ipCooldownSeconds)
}
