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
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/netlinkshim"
	apiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/projectcalico/calico/typha/pkg/discovery"
)

// This file implements a set of functions that are called as part of the felix-start up processing. The purpose is
// primarily focussed on deployments that have HostEncryptionEnabled set to true, and is to fix up routing issues that
// may arise from mismatched routing configuration between nodes.
//
// Note that even when routing is broken between nodes, all nodes should still be able to reach the API server because
// the HostEncryptionEnabled option should only be used for clusters where the control plane nodes are not running
// Calico.
//
// The problem:                          - Turn on wireguard
//                                       - Felix1 and Felix2 restart, install wireguard and publish a public key
// ┌────────────┐        ┌────────────┐  - Felix1 gets a response from Typha1 about the key update for Node2, and
// │     Node1  │        │     Node2  │    programs routing to route to Node2 via Wireguard (since we will encrypt
// │ ┌────────┐ │        │            │    node to node traffic for supporting nodes)
// │ │ Typha1 ◄─┼────────┼──────┐     │  - Felix2 has not yet had an update from Typha1 about the public key for
// │ └────▲───┘ │        │      │     │    Node1, therefore routing to Node1 is still direct and not via Wireguard.
// │ ┌────┴───┐ │        │ ┌────┴───┐ │
// │ │ Felix1 │ │        │ │ Felix2 │ │  We now have broken routing:
// │ └────────┘ │        │ └────────┘ │  - Packets routed over Wireguard from Node1 to Node2 will be dropped by the
// └────────────┘        └────────────┘    Wireguard device on Node2 because Node1 is not one of its known peers.
//                                       - Packets routed direct from Node2 to Node1 will be dropped because of RPF
//                                         checks since the reverse path would be via Wireguard.
//
// With routing broken to typha, Felix2 is then unable to get updated configuration for Node1 to fix its routing.
//
// Since Felix1 does not necessarily connect to its local typha, there can be a chain, or circular mismatched routing.
//
// The current solution. For the most part, most of the following is only valid when HostEncrytpionEnabled is set to
// true. There are some exceptions which are marked in the text below with [**ALL**].
// -  Typha discovery returns the set of available typhas, randomized but with a preference to use the local typha.
//    In most cases, felix will connect to the local typha first. The upshot is that the routing for typha nodes
//    should be (relatively) stable. [**ALL**]
// -  The dataplane daemon during start-up will call into BootstrapHostConnectivity to do the following:
//    -  If wireguard is disabled, remove the wireguard interface and publish an empty key. Typha will pick this up
//       and can distribute the fact that this node is now not running wireguard. With the interface deleted
//       normal routing will resume on this node. Once the typha nodes have fixed up their routing to be direct to this
//       node, this node will then be able to connect to the typha nodes. [**ALL**]
//    -  If wireguard is enabled and the published key does not match the kernel then remove the wireguard interface and
//       publish an empty key (see previous bullet).
// - The dataplane daemon will later call into FilterTyphaEndpoints to filter the set of typha endpoints removing any
//   where we know routing will be broken. This only applies on HostEncryptionEnabled.
//    -  If there is no wireguard routing on this node, or if HostEncryptionEnabled is false, then no endpoints will be
//       filtered out.
//    -  Otherwise, we remove any typha endpoint that is on a node where the node public key is not currently configured
//       in our wireguard routing table. We know this is very unlikely(*) to work because the node with typha will be
//       know our public key and use that to route to us over wireguard. However, we will be routing to typha directly.
//       (*) If typha is on a node whose felix is unable to connect to typha, then it is possible the typha node will
//           not know about our nodes public key and therefore be routing to us directly. In that case including the
//           endpoint would be (transiently) useful. However, since we favor felix connecting to local typha this should
//           be less common.
//       In general it is better to attempt all nodes, but removing nodes that we really should not be able to attach to
//       should decrease the time to successful connection.
// - The dataplane driver has a filtered set of typha endpoints to use.  If it fails to connect to typha then remove all
//   wireguard configuration (interface and published key) before restarting felix.
//
// It's possible that there are multiple flaps before things settle down, but with the local typha preference, things
// seems to settle extremely quickly, with the worst case scenario being a full startup timeout (minimum 40s and will
// scale with the number of typhas) before the local wireguard configuration is removed and felix tries again.

const (
	bootstrapBackoffDuration    = 200 * time.Millisecond
	bootstrapBackoffExpFactor   = 2
	bootstrapBackoffMax         = 2 * time.Second
	bootstrapJitter             = 0.2
	bootstrapMaxRetriesFailFast = 2
	bootstrapMaxRetries         = 5
	boostrapK8sClientTimeout    = 10 * time.Second
)

// BootstrapHostConnectivityAndFilterTyphaAddresses performs wireguard boostrap processing and filtering of typha
// addresses primarily to handle the fact that Host Encryption can cause routing asymmetry due to timing windows
// resulting in felixes being locked out from typhas.
// - If wireguard is disabled then just remove all wireguard configuration from the node (kernel and published key).
// - If the published key and the kernel key don't match remove all wireguard configuraton from the node.
// - If the kernel has no programmed peers then remove all wireguard configuration from the node (since we can't
//   be talking over wireguard yet anyways).
//
// If a set of typha endpoints has been supplied, filter them to exclude endpoints that we know we cannot reach
// due to asymmetric routing.  This will be the case if this node currently has a published wireguard key and:
// - Typha node does not have a public key, but the typha IP address programmed in the kernel as a wireguard peer.
// - Typha node has a public key but the key does not match any of the peer keys programmed in the kernel.
func BootstrapHostConnectivityAndFilterTyphaAddresses(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
	getWireguardHandle func() (netlinkshim.Wireguard, error),
	calicoClient clientv3.Interface,
	typhas []discovery.Typha,
) ([]discovery.Typha, error) {
	wgDeviceName := configParams.WireguardInterfaceName
	nodeName := configParams.FelixHostname

	logCxt := log.WithFields(log.Fields{
		"iface":    wgDeviceName,
		"nodeName": nodeName,
	})
	logCxt.Debug("Bootstrapping wireguard")

	if !configParams.WireguardEnabled || configParams.WireguardInterfaceName == "" {
		// Always remove wireguard configuration if not enabled.
		logCxt.Info("Wireguard is not enabled - ensure no wireguard config")
		return typhas, removeWireguardForBootstrapping(configParams, getNetlinkHandle, calicoClient)
	}

	// FELIX_DBG_WGBOOTSTRAP provides a backdoor way to execute the remaining code without enabling host encryption -
	// used for FV testing.
	_, dbgBootstrapExists := os.LookupEnv("FELIX_DBG_WGBOOTSTRAP")

	if !configParams.WireguardHostEncryptionEnabled && !dbgBootstrapExists {
		// The remaining of the bootstrap processing is only required on clusters that have host encryption enabled
		logCxt.Debug("Host encryption is not enabled - no wireguard bootstrapping required")
		return typhas, nil
	}

	// Get the local public key and the peer public keys currently programmed in the kernel.
	kernelPublicKey, kernelPeerKeys := getWireguardDeviceInfo(logCxt, wgDeviceName, getWireguardHandle)

	// If there is no valid wireguard configuration in the kernel then remove all traces of wireguard.
	if kernelPublicKey == "" || kernelPeerKeys.Len() == 0 {
		logCxt.Info("No valid wireguard kernel routing - removing wireguard configuration completely")
		return typhas, removeWireguardForBootstrapping(configParams, getNetlinkHandle, calicoClient)
	}

	// Get the published public key for this node.
	storedPublicKey, err := getPublicKeyForNode(logCxt, nodeName, calicoClient, bootstrapMaxRetries)
	if err != nil {
		return typhas, err
	}

	if storedPublicKey != kernelPublicKey {
		// The public key configured in the kernel differs from the value stored in the node. Remove all wireguard
		// configuration.
		logCxt.Info("Found mismatch between kernel and datastore wireguard keys - removing wireguard configuration")
		return typhas, removeWireguardForBootstrapping(configParams, getNetlinkHandle, calicoClient)
	}

	// The configured and stored wireguard key match.
	logCxt.WithField("peerKeys", kernelPeerKeys).Info("Wireguard public key matches kernel")

	// If we have any typha endpoints then filter them based on whether wireguard asymetry will prevent access.
	if len(typhas) > 0 {
		filtered := filterTyphaEndpoints(configParams, calicoClient, typhas, kernelPeerKeys)

		if len(filtered) == 0 {
			// We have filtered out all of the typha endpoints, i.e. with our current wireguard configuration none of
			// the typhas will be accessible due to asymmetric routing. Best thing to do is just delete our wireguard
			// configuration after which all of the typha endpoints should eventually become acceessible.
			log.Warning("None of the typhas will be accessible due to wireguard routing asymmetry - remove wireguard")
			return typhas, removeWireguardForBootstrapping(configParams, getNetlinkHandle, calicoClient)
		}

		return filtered, nil
	}

	return typhas, nil
}

// RemoveWireguardConditionallyOnBootstrap removes all wireguard configuration based on
// configuration conditions. This includes:
// - The wireguard public key
// - The wireguard device (which in turn will delete all wireguard routing rules).
func RemoveWireguardConditionallyOnBootstrap(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
	calicoClient clientv3.Interface,
) error {
	/*
		| WireguardEnabled | WireguardHostEncryptionEnabled | Clear Wireguard PK + Device? |
		|------------------|--------------------------------|------------------------------|
		| YES			   | NO								| NO						   |
		| YES			   | YES							| NO						   |
		| NO			   | NO								| YES						   |
		| NO			   | YES							| YES						   |
	*/
	if !configParams.WireguardEnabled || !configParams.WireguardHostEncryptionEnabled {
		log.Debug("No host encryption - not necessary to remove wireguard configuration")
		return nil
	}

	return removeWireguardForBootstrapping(configParams, getNetlinkHandle, calicoClient)
}

// filterTyphaEndpoints filters the supplied set of typha endpoints to the set where wireguard routing is most likely
// to succeed. Any errors encountered are swallowed and the associated peer is just included.
func filterTyphaEndpoints(
	configParams *config.Config,
	calicoClient clientv3.Interface,
	typhas []discovery.Typha,
	peers set.Set,
) []discovery.Typha {
	log.Debugf("Filtering typha endpoints for wireguard: %v", typhas)

	var filtered []discovery.Typha

	for _, typha := range typhas {
		logCxt := log.WithField("typhaAddr", typha.Addr)
		if typha.NodeName == nil {
			logCxt.Debug("Typha endpoint has no node information - include typha endpoint")
			filtered = append(filtered, typha)
			continue
		}

		typhaNodeName := *typha.NodeName
		logCxt = logCxt.WithField("typhaNodeName", typhaNodeName)
		if typhaNodeName == configParams.FelixHostname {
			// This is a local typha. We should always be able to connect.
			logCxt.Info("Typha endpoint is local - include typha endpoint")
			filtered = append(filtered, typha)
			continue
		}

		// Get the public key configured for the typha node. Better to just include more typha nodes than we think will
		// work, so fail fast when getting the node.
		typhaNodeKey, err := getPublicKeyForNode(logCxt, typhaNodeName, calicoClient, bootstrapMaxRetriesFailFast)
		if err != nil {
			// If we were unable to determine the public key then just include the endpoint.
			logCxt.WithError(err).Info("Unable to determine public key for node")
			filtered = append(filtered, typha)
			continue
		}
		logCxt = logCxt.WithField("typhaNodeKey", typhaNodeKey)

		if typhaNodeKey == "" {
			// There is no key configured and we don't have it in our kernel routing table. Include this typha.
			logCxt.Info("Typha node does not have a wireguard key and not in kernel - include typha endpoint")
			filtered = append(filtered, typha)
		} else if peers.Contains(typhaNodeKey) {
			// The public key on the typha node is configured in the local routing table. Include this typha.
			logCxt.Debug("Typha node has a wireguard key that is in the local wireguard routing table - include typha endpoint")
			filtered = append(filtered, typha)
		} else {
			// The public key on the typha node is not configured in the local routing table. There is no point in
			// including this typha because routing will not work and we'll take longer to find a working typha.
			logCxt.Warning("Typha node has wireguard key that is not in the local wireguard routing table - exclude typha endpoint")
		}
	}

	log.Infof("Filtered typha endpoints: %v", filtered)

	return filtered
}

// removeWireguardForBootstrapping unconditionally removes all wireguard configuration. This includes:
// - The wireguard public key
// - The wireguard device (which in turn will delete all wireguard routing rules).
func removeWireguardForBootstrapping(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
	calicoClient clientv3.Interface,
) error {
	var errors []error
	// Remove all wireguard configuration that we can.
	if err := removeWireguardDevice(configParams, getNetlinkHandle); err != nil {
		errors = append(errors, fmt.Errorf("cannot remove wireguard device: %w", err))
	}
	if err2 := removeWireguardPublicKey(configParams, calicoClient); err2 != nil {
		errors = append(errors, fmt.Errorf("cannot remove wireguard public key: %w", err2))
	}
	if len(errors) > 0 {
		return fmt.Errorf("encountered errors during wireguard device bootstrap: %v", errors)
	}

	return nil
}

// getPublicKeyForNode returns the configured wireguard public key for a given node.
func getPublicKeyForNode(logCxt *log.Entry, nodeName string, calicoClient clientv3.Interface, maxRetries int) (string, error) {
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
	for r := 0; r < maxRetries; r++ {
		cxt, cancel := context.WithTimeout(context.Background(), boostrapK8sClientTimeout)
		node, err = calicoClient.Nodes().Get(cxt, nodeName, options.GetOptions{})
		cancel()
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			// If the node does not exist then it's not going ot have a wireguard public key configured.
			logCxt.Info("Node does not exist - no published wireguard key")
			return "", nil
		} else if err != nil {
			logCxt.WithError(err).Warn("Couldn't fetch node config from datastore, retrying")
			<-expBackoffMgr.Backoff().C() // safe to block here as we're not dependent on other threads
			continue
		}

		return node.Status.WireguardPublicKey, nil
	}

	return "", fmt.Errorf("couldn't determine public key configured for node after %d retries: %v", maxRetries, err)
}

// getWireguardDeviceInfo attempts to fetch the current wireguard state from the kernel:
// - Public key
// - Set of peer public keys
func getWireguardDeviceInfo(
	logCxt *log.Entry, wgIfaceName string, getWireguardHandle func() (netlinkshim.Wireguard, error),
) (string, set.Set) {
	wg, err := getWireguardHandle()
	if err != nil {
		logCxt.Info("Couldn't acquire wireguard handle")
		return "", nil
	}
	defer func() {
		if err = wg.Close(); err != nil {
			logCxt.WithError(err).Info("Couldn't close wireguard handle")
		}
	}()

	dev, err := wg.DeviceByName(wgIfaceName)
	if err != nil {
		logCxt.WithError(err).Info("Couldn't find wireguard device, assuming no wireguard config")
		return "", nil
	}

	if dev.PublicKey == zeroKey {
		// No public key on device - treat as no config.
		logCxt.Info("No public key configured on device")
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
		cxt, cancel := context.WithTimeout(context.Background(), boostrapK8sClientTimeout)
		thisNode, err = calicoClient.Nodes().Get(cxt, nodeName, options.GetOptions{})
		cancel()
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			// If the node does not exist then it's not going ot have a wireguard public key configured.
			logCxt.Info("Node does not exist - no published wireguard key to remove")
			return nil
		} else if err != nil {
			logCxt.WithError(err).Warn("Couldn't fetch node config from datastore, retrying")
			<-expBackoffMgr.Backoff().C() // safe to block here as we're not dependent on other threads
			continue
		}

		// if there is any config mismatch, wipe the datastore's publickey (forces peers to send unencrypted traffic)
		if thisNode.Status.WireguardPublicKey != "" {
			logCxt.Info("Wireguard key set on node - removing")
			thisNode.Status.WireguardPublicKey = ""
			cxt, cancel = context.WithTimeout(context.Background(), boostrapK8sClientTimeout)
			_, err = calicoClient.Nodes().Update(cxt, thisNode, options.SetOptions{})
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
