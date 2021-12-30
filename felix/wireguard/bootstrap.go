// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

package wireguard

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// BootstrapHostConnectivity forces WireGuard peers with hostencryption enabled to communicate with this node unencrypted.
// This ensures connectivity in scenarios where we have lost our WireGuard config, but will be sent WireGuard traffic
// e.g. after a node restart, during felix startup, when we need to fetch config from Typha (calico/issues/5125)
func BootstrapHostConnectivity(wgDeviceName string, nodeName string, getWireguardHandle func() (netlinkshim.Wireguard, error), calicoClient clientv3.Interface) error {
	var storedPublicKey string
	var kernelPublicKey string

	wg, err := getWireguardHandle()
	if err != nil {
		log.Debug("Couldn't acquire WireGuard handle, treating public key as unset")
	} else {
		kernelPublicKey = getPublicKey(wgDeviceName, wg).String()
		defer wg.Close()
	}

	// make a few attempts to read our publickey from the datastore, compare, and update if required
	maxRetries := 3
	for r := 0; r < maxRetries; r++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		thisNode, err := calicoClient.Nodes().Get(ctx, nodeName, options.GetOptions{})
		cancel()
		if err != nil {
			log.WithError(err).Debug("Couldn't fetch node config from datastore, retrying")
			continue
		}

		storedPublicKey = thisNode.Status.WireguardPublicKey

		// if there is any config mismatch, wipe the datastore's publickey (forces peers to send unencrypted traffic)
		if storedPublicKey != kernelPublicKey {
			log.Debug("Found mismatch between kernel and datastore WireGuard keys. Clearing stale key from datastore")
			thisNode.Status.WireguardPublicKey = ""
			ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			_, err := calicoClient.Nodes().Update(ctx, thisNode, options.SetOptions{})
			cancel()
			if err != nil {
				switch err.(type) {
				case cerrors.ErrorResourceUpdateConflict:
					log.Debug("Conflict while clearing WireGuard config, retrying update")
					continue
				}

				return fmt.Errorf("failed to clear WireGuard config: %w", err)
			}
			log.Debug("Cleared WireGuard public key from datastore")
		}
		return nil
	}

	return fmt.Errorf("couldn't bootstrap host connecivity after %d retries", maxRetries)
}

// getPublicKey attempts to fetch a wireguard key from the kernel statelessly
// this is intended for use during startup; an error may simply mean wireguard is not configured
func getPublicKey(wgIfaceName string, wg netlinkshim.Wireguard) wgtypes.Key {
	dev, err := wg.DeviceByName(wgIfaceName)
	if err != nil {
		log.WithError(err).Debugf("Couldn't find WireGuard device '%s', reporting unset key", wgIfaceName)
		return zeroKey
	}

	return dev.PublicKey
}
