// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/netlinkshim"
	apiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const (
	bootstrapBackoffDuration  = 200 * time.Millisecond
	bootstrapBackoffExpFactor = 2
	bootstrapBackoffMax       = 2 * time.Second
	bootstrapJitter           = 0.2
	bootstrapMaxRetries       = 5
)

// BootstrapHostConnectivity forces WireGuard peers with hostencryption enabled to communicate with this node unencrypted.
// This ensures connectivity in scenarios where we have lost our WireGuard config, but will be sent WireGuard traffic
// e.g. after a node restart, during felix startup, when we need to fetch config from Typha (calico/issues/5125)
func BootstrapHostConnectivity(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
	getWireguardHandle func() (netlinkshim.Wireguard, error),
	calicoClient clientv3.Interface,
) error {
	wgDeviceName := configParams.WireguardInterfaceName
	nodeName := configParams.FelixHostname

	logCtx := log.WithFields(log.Fields{
		"iface":    wgDeviceName,
		"hostName": nodeName,
		"ref":      "wgBootstrap",
	})

	if !configParams.WireguardHostEncryptionEnabled {
		// HostEncryption is currently enabled in environments by operator rather than through FelixConfiguration.
		// This should not change for a given deployment. We only need to handle bootstrapping for clusters where
		// host encryption is enabled.
		logCtx.Debug("Host encryption is not enabled - no wireguard bootstrapping required")
	}

	logCtx.Debug("Bootstrapping wireguard")

	if !configParams.WireguardEnabled || configParams.WireguardInterfaceName == "" {
		logCtx.Info("Wireguard is not enabled - ensure no wireguard config")
		return RemoveWireguardForHostEncryptionBootstrapping(configParams, getNetlinkHandle, calicoClient)
	}

	wg, err := getWireguardHandle()
	if err != nil {
		logCtx.Info("Couldn't acquire wireguard handle, remove configuration")
		return RemoveWireguardForHostEncryptionBootstrapping(configParams, getNetlinkHandle, calicoClient)
	}
	defer func() {
		err = wg.Close()
		logCtx.WithError(err).Info("Couldn't close wireguard handle")
	}()

	var storedPublicKey string
	var kernelPublicKey string
	expBackoffMgr := wait.NewExponentialBackoffManager(
		bootstrapBackoffDuration,
		bootstrapBackoffMax,
		time.Minute,
		bootstrapBackoffExpFactor,
		bootstrapJitter,
		clock.RealClock{},
	)
	defer expBackoffMgr.Backoff().Stop()

	// Get the public key currently programmed in the kernel.
	kernelPublicKey = getPublicKey(logCtx, wgDeviceName, wg).String()

	// Make a few attempts to read our publickey from the datastore, compare. If different, remove all wireguard
	// configuration.
	for r := 0; r < bootstrapMaxRetries; r++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		thisNode, err := calicoClient.Nodes().Get(ctx, nodeName, options.GetOptions{})
		cancel()
		if err != nil {
			logCtx.WithError(err).Warn("Couldn't fetch node config from datastore, retrying")
			<-expBackoffMgr.Backoff().C() // safe to block here as we're not dependent on other threads
			continue
		}

		// If there is any config mismatch, wipe the datastore's publickey (forces peers to send unencrypted traffic).
		// Once connected and sync'd the key will be regenerated and propagated.
		storedPublicKey = thisNode.Status.WireguardPublicKey
		if storedPublicKey != kernelPublicKey {
			logCtx.Info("Found mismatch between kernel and datastore wireguard keys - removing wireguard configuration")
			return RemoveWireguardForHostEncryptionBootstrapping(configParams, getNetlinkHandle, calicoClient)
		}
		return nil
	}

	// Couldn't determine the current wireguard configuration.
	return fmt.Errorf("couldn't determine current wireguard configuration after %d retries", bootstrapMaxRetries)
}

// RemoveWireguardForHostEncryptionBootstrapping removes all wireguard configuration. This includes:
// - The wireguard public key
// - The wireguard device (which in turn will delete all wireguard routing rules).
func RemoveWireguardForHostEncryptionBootstrapping(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
	calicoClient clientv3.Interface,
) error {
	wgDeviceName := configParams.WireguardInterfaceName
	nodeName := configParams.FelixHostname

	logCtx := log.WithFields(log.Fields{
		"iface":    wgDeviceName,
		"hostName": nodeName,
	})

	if !configParams.WireguardHostEncryptionEnabled {
		// HostEncryption is currently enabled in environments by operator rather than through FelixConfiguration.
		// This should not change for a given deployment. We only need to handle bootstrapping for clusters where
		// host encryption is enabled.
		logCtx.Debug("Host encryption is not enabled - no wireguard bootstrapping required")
	}

	// Remove all wireguard configuration that we can.
	err1 := removeWireguardDevice(configParams, getNetlinkHandle)
	err2 := removeWireguardPublicKey(configParams, calicoClient)

	if err1 != nil {
		return err1
	} else if err2 != nil {
		return err2
	}
	return nil
}

// removeWireguardDevice removes the wireguard device
func removeWireguardDevice(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
) error {
	wgDeviceName := configParams.WireguardInterfaceName
	nodeName := configParams.FelixHostname

	logCtx := log.WithFields(log.Fields{
		"iface":    wgDeviceName,
		"hostName": nodeName,
	})

	if wgDeviceName == "" {
		logCtx.Debug("No wireguard device specified")
		return nil
	}

	logCtx.Debug("Removing wireguard device")

	expBackoffMgr := wait.NewExponentialBackoffManager(
		bootstrapBackoffDuration,
		bootstrapBackoffMax,
		time.Minute,
		bootstrapBackoffExpFactor,
		bootstrapJitter,
		clock.RealClock{},
	)
	defer expBackoffMgr.Backoff().Stop()

	// Make a few attempts to delete the wireguard device.
	var err error
	var handle netlinkshim.Interface
	for r := 0; r < bootstrapMaxRetries; r++ {
		if handle == nil {
			if handle, err = getNetlinkHandle(); err != nil {
				<-expBackoffMgr.Backoff().C()
				continue
			}
			defer handle.Delete()
		}
		if err = removeLink(wgDeviceName, handle); err != nil {
			<-expBackoffMgr.Backoff().C()
			continue
		}
		return nil
	}

	return fmt.Errorf("couldn't remove wireguard device after %d retries: %v", bootstrapMaxRetries, err)
}

// removeWireguardPublicKey removes the public key from the node.
func removeWireguardPublicKey(
	configParams *config.Config,
	calicoClient clientv3.Interface,
) error {
	nodeName := configParams.FelixHostname

	logCtx := log.WithFields(log.Fields{
		"hostName": nodeName,
	})

	logCtx.Debug("Removing wireguard public key")

	expBackoffMgr := wait.NewExponentialBackoffManager(
		bootstrapBackoffDuration,
		bootstrapBackoffMax,
		time.Minute,
		bootstrapBackoffExpFactor,
		bootstrapJitter,
		clock.RealClock{},
	)
	defer expBackoffMgr.Backoff().Stop()

	// Make a few attempts to remove the public key from the datastore.
	var err error
	var thisNode *apiv3.Node
	for r := 0; r < bootstrapMaxRetries; r++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		thisNode, err = calicoClient.Nodes().Get(ctx, nodeName, options.GetOptions{})
		cancel()
		if err != nil {
			logCtx.WithError(err).Warn("Couldn't fetch node config from datastore, retrying")
			<-expBackoffMgr.Backoff().C() // safe to block here as we're not dependent on other threads
			continue
		}

		// if there is any config mismatch, wipe the datastore's publickey (forces peers to send unencrypted traffic)
		if thisNode.Status.WireguardPublicKey != "" {
			logCtx.Info("Wireguard key set on node - removing")
			thisNode.Status.WireguardPublicKey = ""
			ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			_, err = calicoClient.Nodes().Update(ctx, thisNode, options.SetOptions{})
			cancel()
			if err != nil {
				switch err.(type) {
				case cerrors.ErrorResourceUpdateConflict:
					logCtx.Infof("Conflict while clearing wireguard config, retrying update (%v)", err)
				default:
					logCtx.Errorf("Failed to clear wireguard config: %v", err)
				}
				<-expBackoffMgr.Backoff().C()
				continue
			}
			logCtx.Info("Cleared wireguard public key from datastore")
		} else {
			logCtx.Info("Wireguard public key not set in datastore")
		}
		return nil
	}

	return fmt.Errorf("couldn't delete wireguard public key after %d retries: %v", bootstrapMaxRetries, err)
}

// getPublicKey attempts to fetch a wireguard key from the kernel statelessly
// this is intended for use during startup; an error may simply mean wireguard is not configured
func getPublicKey(log *log.Entry, wgIfaceName string, wg netlinkshim.Wireguard) wgtypes.Key {
	dev, err := wg.DeviceByName(wgIfaceName)
	if err != nil {
		log.WithError(err).Debugf("Couldn't find wireguard device '%s', reporting unset key", wgIfaceName)
		return zeroKey
	}
	return dev.PublicKey
}

// removeLink removes the named link.
func removeLink(name string, netlinkClient netlinkshim.Interface) error {
	logCxt := log.WithField("ifaceName", name)
	link, err := netlinkClient.LinkByName(name)
	if err == nil {
		logCxt.Info("Deleting device")
		if err := netlinkClient.LinkDel(link); err != nil {
			log.WithError(err).Error("Error deleting wireguard type link")
			return err
		}
		logCxt.Info("Deleted device")
	} else if netlinkshim.IsNotExist(err) {
		logCxt.Debug("Device does not exist")
	} else if err != nil {
		logCxt.WithError(err).Error("Unable to determine if device exists")
		return err
	}
	return nil
}
