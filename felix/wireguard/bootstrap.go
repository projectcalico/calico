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

	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/projectcalico/calico/typha/pkg/discovery"

	log "github.com/sirupsen/logrus"
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

// BootstrapHostConnectivity forces WireGuard peers with host encryption to communicate with this node unencrypted.
// This ensures connectivity in scenarios where we have lost our WireGuard config, but will be sent WireGuard traffic
// e.g. after a node restart, during felix startup, when we need to fetch config from Typha (calico/issues/5125)
//
// Returns the set of programmed peers to validate. Returns nil if wireguard configuration is not present, has just been
// removed, or host encryption is not enabled.
func BootstrapHostConnectivity(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
	getWireguardHandle func() (netlinkshim.Wireguard, error),
	calicoClient clientv3.Interface,
) (set.Set, error) {
	wgDeviceName := configParams.WireguardInterfaceName
	nodeName := configParams.FelixHostname

	logCxt := log.WithFields(log.Fields{
		"iface":    wgDeviceName,
		"nodeName": nodeName,
	})

	if !configParams.WireguardHostEncryptionEnabled {
		// HostEncryption is currently enabled in environments by operator rather than through FelixConfiguration.
		// This should not change for a given deployment. We only need to handle bootstrapping for clusters where
		// host encryption is enabled.
		logCxt.Debug("Host encryption is not enabled - no wireguard bootstrapping required")
		return nil, nil
	}

	logCxt.Debug("Bootstrapping wireguard")

	if !configParams.WireguardEnabled || configParams.WireguardInterfaceName == "" {
		logCxt.Info("Wireguard is not enabled - ensure no wireguard config")
		return nil, RemoveWireguardForHostEncryptionBootstrapping(configParams, getNetlinkHandle, calicoClient)
	}

	wg, err := getWireguardHandle()
	if err != nil {
		logCxt.Info("Couldn't acquire wireguard handle, remove configuration")
		return nil, RemoveWireguardForHostEncryptionBootstrapping(configParams, getNetlinkHandle, calicoClient)
	}
	defer func() {
		err = wg.Close()
		logCxt.WithError(err).Info("Couldn't close wireguard handle")
	}()

	// Get the local public key and the peer public keys currently programmed in the kernel.
	kernelPublicKey, kernelPeerKeys := getWireguardInfo(logCxt, wgDeviceName, getWireguardHandle)

	// If there is no valid wireguard configuration in the kernel then remove all traces of wireguard.
	if kernelPublicKey == "" || kernelPeerKeys.Len() == 0 {
		logCxt.Info("No valid wireguard kernel routing - removing wireguard configuration completely")
		return nil, RemoveWireguardForHostEncryptionBootstrapping(configParams, getNetlinkHandle, calicoClient)
	}

	storedPublicKey, err := getPublicKeyForNode(logCxt, nodeName, calicoClient)
	if err != nil {
		// Could not determine the public key for this node.
		return nil, fmt.Errorf("couldn't determine current wireguard configuration after %d retries: %v", bootstrapMaxRetries, err)
	}

	if storedPublicKey != kernelPublicKey {
		// The public key configured in the kernel differs from the value stored in the node. Remove all wireguard
		// configuration.
		logCxt.Info("Found mismatch between kernel and datastore wireguard keys - removing wireguard configuration")
		return nil, RemoveWireguardForHostEncryptionBootstrapping(configParams, getNetlinkHandle, calicoClient)
	}

	// The configured and stored wireguard key match.
	logCxt.Infof("Wireguard public key matches kernel - we have %d configured peers", kernelPeerKeys.Len())
	return kernelPeerKeys, nil
}

func FilterTyphaEndpoints(
	configParams *config.Config,
	v3Client clientv3.Interface,
	typhas []discovery.Typha,
	peersToValidate set.Set,
) ([]discovery.Typha, error) {
	if peersToValidate == nil {
		log.Debug("No peers to validate")
		return typhas, nil
	}

	logCxt := log.WithFields(log.Fields{
		"iface": configParams.WireguardInterfaceName,
	})
	logCxt.Debug("Filtering typha endpoints for wireguard")

	var filtered []discovery.Typha

	for _, typha := range typhas {
		if typha.NodeName == nil {
			logCxt.Infof("Typha endpoint %s has no node information - include typha endpoint", typha.Addr)
			filtered = append(filtered, typha)
			continue
		}

		typhaNodeKey, err := getPublicKeyForNode(logCxt, *typha.NodeName, v3Client)
		if err != nil {
			logCxt.WithError(err).Infof("Unable to determine public key for node %s", *typha.NodeName)
			return nil, err
		}
		if typhaNodeKey == "" {
			logCxt.Infof("Typha node %s does not have a wireguard key - include typha endpoint", *typha.NodeName)
			filtered = append(filtered, typha)
		} else if peersToValidate.Contains(typhaNodeKey) {
			logCxt.Infof("Typha node %s has a wireguard key that is in the local wireguard routing table - include typha endpoint", *typha.NodeName)
			filtered = append(filtered, typha)
		} else {
			logCxt.Warningf("Typha node %s has a wireguard key that is not in the local wireguard routing table - exclude typha endpoint", *typha.NodeName)
		}
	}

	logCxt.Infof("Filtered typha endpoints: %v", filtered)

	return filtered, nil
}

// RemoveWireguardForHostEncryptionBootstrapping removes all wireguard configuration. This includes:
// - The wireguard public key
// - The wireguard device (which in turn will delete all wireguard routing rules).
func RemoveWireguardForHostEncryptionBootstrapping(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
	calicoClient clientv3.Interface,
) error {
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

func getPublicKeyForNode(logCxt *log.Entry, nodeName string, calicoClient clientv3.Interface) (string, error) {
	expBackoffMgr := wait.NewExponentialBackoffManager(
		bootstrapBackoffDuration,
		bootstrapBackoffMax,
		time.Minute,
		bootstrapBackoffExpFactor,
		bootstrapJitter,
		clock.RealClock{},
	)
	defer expBackoffMgr.Backoff().Stop()

	var err error
	var node *apiv3.Node
	for r := 0; r < bootstrapMaxRetries; r++ {
		Cxt, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		node, err = calicoClient.Nodes().Get(Cxt, nodeName, options.GetOptions{})
		cancel()
		if err != nil {
			logCxt.WithError(err).Warn("Couldn't fetch node config from datastore, retrying")
			<-expBackoffMgr.Backoff().C() // safe to block here as we're not dependent on other threads
			continue
		}

		return node.Status.WireguardPublicKey, nil
	}

	return "", err
}

// getWireguardInfo attempts to fetch the current wireguard state:
// - Public key
// - Set of peer public keys
func getWireguardInfo(
	logCxt *log.Entry, wgIfaceName string, getWireguardHandle func() (netlinkshim.Wireguard, error),
) (string, set.Set) {
	wg, err := getWireguardHandle()
	if err != nil {
		logCxt.Info("Couldn't acquire wireguard handle")
		return "", nil
	}
	defer func() {
		err = wg.Close()
		logCxt.WithError(err).Info("Couldn't close wireguard handle")
	}()

	dev, err := wg.DeviceByName(wgIfaceName)
	if err != nil {
		logCxt.WithError(err).Debug("Couldn't find wireguard device, assuming no wireguard config")
		return "", nil
	}

	if dev.PublicKey == zeroKey {
		// No public key on device - treat as no config.
		logCxt.Debug("No public key configured on device")
		return "", nil
	}

	// Construct the set of peer public keys.
	peers := set.New()
	for _, peer := range dev.Peers {
		if peer.PublicKey != zeroKey {
			peers.Add(peer.PublicKey.String())
		}
	}

	// Return the public key and the set of peer keys that are configured in the kernel.
	return dev.PublicKey.String(), peers
}

// removeWireguardDevice removes the wireguard device
func removeWireguardDevice(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
) error {
	wgDeviceName := configParams.WireguardInterfaceName
	nodeName := configParams.FelixHostname

	logCxt := log.WithFields(log.Fields{
		"iface":    wgDeviceName,
		"nodeName": nodeName,
	})

	if wgDeviceName == "" {
		logCxt.Debug("No wireguard device specified")
		return nil
	}

	logCxt.Debug("Removing wireguard device")

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
		if err = removeDevice(logCxt, wgDeviceName, handle); err != nil {
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

	logCxt := log.WithFields(log.Fields{
		"nodeName": nodeName,
	})

	logCxt.Debug("Removing wireguard public key")

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
		Cxt, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		thisNode, err = calicoClient.Nodes().Get(Cxt, nodeName, options.GetOptions{})
		cancel()
		if err != nil {
			logCxt.WithError(err).Warn("Couldn't fetch node config from datastore, retrying")
			<-expBackoffMgr.Backoff().C() // safe to block here as we're not dependent on other threads
			continue
		}

		// if there is any config mismatch, wipe the datastore's publickey (forces peers to send unencrypted traffic)
		if thisNode.Status.WireguardPublicKey != "" {
			logCxt.Info("Wireguard key set on node - removing")
			thisNode.Status.WireguardPublicKey = ""
			Cxt, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			_, err = calicoClient.Nodes().Update(Cxt, thisNode, options.SetOptions{})
			cancel()
			if err != nil {
				switch err.(type) {
				case cerrors.ErrorResourceUpdateConflict:
					logCxt.Infof("Conflict while clearing wireguard config, retrying update (%v)", err)
				default:
					logCxt.Errorf("Failed to clear wireguard config: %v", err)
				}
				<-expBackoffMgr.Backoff().C()
				continue
			}
			logCxt.Info("Cleared wireguard public key from datastore")
		} else {
			logCxt.Info("Wireguard public key not set in datastore")
		}
		return nil
	}

	return fmt.Errorf("couldn't delete wireguard public key after %d retries: %v", bootstrapMaxRetries, err)
}

// removeDevice removes the named link.
func removeDevice(logCxt *log.Entry, name string, netlinkClient netlinkshim.Interface) error {
	link, err := netlinkClient.LinkByName(name)
	if err == nil {
		logCxt.Info("Deleting device")
		if err := netlinkClient.LinkDel(link); err != nil {
			log.WithError(err).Error("Error deleting device")
			return err
		}
		logCxt.Info("Deleted wireguard device")
	} else if netlinkshim.IsNotExist(err) {
		logCxt.Debug("Device does not exist")
	} else if err != nil {
		logCxt.WithError(err).Error("Unable to determine if device exists")
		return err
	}
	return nil
}
