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

//go:build linux

package wireguard

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"

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
// primarily focused on deployments that have HostEncryptionEnabled set to true, and is to fix up routing issues that
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
// -  The dataplane daemon during start-up will call into BootstrapAndFilterTyphaAddresses to do the
//    following:
//    -  If wireguard is disabled, remove the wireguard interface and publish an empty key. Typha will pick this up
//       and can distribute the fact that this node is now not running wireguard. With the interface deleted
//       normal routing will resume on this node. Once the typha nodes have fixed up their routing to be direct to this
//       node, this node will then be able to connect to the typha nodes. [**ALL**]
//    -  If wireguard is enabled and the published key does not match the kernel then remove the wireguard interface and
//       publish an empty key (see previous bullet).
//    -  Filter the supplied set of typha addresses to removes addresses where connectivity will be broken:
//       -  If there is no wireguard routing on this node, or if HostEncryptionEnabled is false, then no endpoints will
//          be filtered out.
//       -  Otherwise, we remove any typha endpoint that is on a node where the node public key is not currently
//          configured in our wireguard routing table. We know this is very unlikely(*) to work because the node with
//          typha will be know our public key and use that to route to us over wireguard. However, we will be routing to
//          typha directly.
//          (*) If typha is on a node whose felix is unable to connect to typha, then it is possible the typha node will
//              not know about our nodes public key and therefore be routing to us directly. In that case including the
//              endpoint would be (transiently) useful. However, since we favor felix connecting to local typha this
//              should be less common.
//          In general it is better to attempt all nodes, but removing nodes that we really should not be able to attach
//          to should decrease the time to successful connection.
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

// BootstrapAndFilterTyphaAddresses performs wireguard bootstrap processing and filtering of typha addresses. This is
// primarily to handle the fact that Host Encryption can cause routing asymmetry due to timing windows. This results in
// felixes being locked out from typhas.
//   - If wireguard is disabled then just remove all wireguard configuration from the node (kernel and published key).
//     We do this whether host encryption is enabled or not.
//
// For host encryption only:
//   - If the published key and the kernel key don't match remove all wireguard configuration from the node.
//   - If the kernel has no programmed peers then remove all wireguard configuration from the node (since we can't
//     be talking over wireguard yet anyways).
//   - If a set of typha endpoints has been supplied, filter them to exclude endpoints that we know we cannot reach
//     due to asymmetric routing.  This will be the case if this node currently has a published wireguard key and:
//   - Typha node does not have a public key, but the typha IP address programmed in the kernel as a wireguard peer.
//   - Typha node has a public key but the key does not match any of the peer keys programmed in the kernel.
//
// -----
//
// Note that if a non-empty slice of typha endpoints has been supplied this will *always* return a non-empty slice of
// endpoints. In the scenario where all typha addresses would be filtered out, wireguard configuration is removed from
// the node and then all typha addresses are returned.
func BootstrapAndFilterTyphaAddresses(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
	getWireguardHandle func() (netlinkshim.Wireguard, error),
	calicoClient clientv3.Interface,
	typhas []discovery.Typha,
) ([]discovery.Typha, error) {
	var (
		typhasV4, typhasV6 []discovery.Typha
		err                error
		errors             []error
	)

	// Split typhas slice into separate v4 and v6 slices
	for _, typha := range typhas {
		ipStr, _, err := net.SplitHostPort(typha.Addr)
		if err != nil {
			errors = append(errors, fmt.Errorf("error parsing Typha address %v: %w", typha.Addr, err))
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			errors = append(errors, fmt.Errorf("could not parse Typha address %v", typha.Addr))
		}

		if ip.To4() != nil {
			typhasV4 = append(typhasV4, typha)
		} else {
			typhasV6 = append(typhasV6, typha)
		}
	}

	typhasV4, err = bootstrapAndFilterTyphaAddressesForIPVersion(configParams, getNetlinkHandle, getWireguardHandle, calicoClient, typhasV4, 4)
	if err != nil {
		errors = append(errors, fmt.Errorf("error bootstrapping IPv4 wireguard: %w", err))
	}

	typhasV6, err = bootstrapAndFilterTyphaAddressesForIPVersion(configParams, getNetlinkHandle, getWireguardHandle, calicoClient, typhasV6, 6)
	if err != nil {
		errors = append(errors, fmt.Errorf("error bootstrapping IPv6 wireguard: %w", err))
	}

	// Merge filtered v4 and v6 typhas back
	filteredTyphas := append(typhasV4, typhasV6...)

	if len(errors) > 0 {
		return typhas, fmt.Errorf("encountered errors during wireguard bootstrap: %v", errors)
	}

	return filteredTyphas, nil
}

func bootstrapAndFilterTyphaAddressesForIPVersion(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
	getWireguardHandle func() (netlinkshim.Wireguard, error),
	calicoClient clientv3.Interface,
	typhas []discovery.Typha,
	ipVersion uint8,
) ([]discovery.Typha, error) {
	nodeName := configParams.FelixHostname

	wgEnabled := configParams.WireguardEnabled
	wgDeviceName := configParams.WireguardInterfaceName

	if ipVersion == 6 {
		wgEnabled = configParams.WireguardEnabledV6
		wgDeviceName = configParams.WireguardInterfaceNameV6
	} else if ipVersion != 4 {
		return typhas, fmt.Errorf("unknown IP version: %d", ipVersion)
	}

	logCtx := log.WithFields(log.Fields{
		"ipVersion": ipVersion,
		"iface":     wgDeviceName,
		"nodeName":  nodeName,
	})
	logCtx.Debug("Bootstrapping wireguard")

	if !wgEnabled || wgDeviceName == "" {
		// Always remove wireguard configuration if not enabled.
		logCtx.Info("Wireguard is not enabled - ensure no wireguard config")
		return typhas, removeWireguardForBootstrapping(configParams, getNetlinkHandle, calicoClient, ipVersion)
	}

	// FELIX_DBG_WGBOOTSTRAP provides a backdoor way to execute the remaining code without enabling host encryption -
	// used for FV testing.
	_, dbgBootstrapExists := os.LookupEnv("FELIX_DBG_WGBOOTSTRAP")

	if !configParams.WireguardHostEncryptionEnabled && !dbgBootstrapExists {
		// The remaining of the bootstrap processing is only required on clusters that have host encryption enabled
		logCtx.Debug("Host encryption is not enabled - no wireguard bootstrapping required")
		return typhas, nil
	}

	// Get the local public key and the peer public keys currently programmed in the kernel.
	kernelPublicKey, kernelPeerKeys := getWireguardDeviceInfo(logCtx, wgDeviceName, getWireguardHandle)

	// If there is no useful wireguard configuration in the kernel then remove all traces of wireguard.
	if kernelPublicKey == "" || kernelPeerKeys.Len() == 0 {
		logCtx.Info("No valid wireguard kernel routing - removing wireguard configuration completely")
		return typhas, removeWireguardForBootstrapping(configParams, getNetlinkHandle, calicoClient, ipVersion)
	}

	// Get the published public key for this node.
	storedPublicKey, err := getPublicKeyForNode(logCtx, nodeName, calicoClient, bootstrapMaxRetries, ipVersion)
	if err != nil {
		return typhas, err
	}

	if storedPublicKey != kernelPublicKey {
		// The public key configured in the kernel differs from the value stored in the node. Remove all wireguard
		// configuration.
		logCtx.Info("Found mismatch between kernel and datastore wireguard keys - removing wireguard configuration")
		return typhas, removeWireguardForBootstrapping(configParams, getNetlinkHandle, calicoClient, ipVersion)
	}

	// The configured and stored wireguard key match.
	logCtx.WithField("peerKeys", kernelPeerKeys).Info("Wireguard public key matches kernel")

	// If we have any typha endpoints then filter them based on whether wireguard asymmetry will prevent access.
	// It is possible, that there will be no typhas - in this case the nodes are connecting directly to the API server.
	if len(typhas) > 0 {
		filtered := filterTyphaEndpoints(configParams, calicoClient, typhas, kernelPeerKeys, ipVersion)

		if len(filtered) == 0 {
			// We have filtered out all of the typha endpoints, i.e. with our current wireguard configuration none of
			// the typhas will be accessible due to asymmetric routing. Best thing to do is just delete our wireguard
			// configuration after which all of the typha endpoints should eventually become acceessible.
			logCtx.Warning("None of the typhas will be accessible due to wireguard routing asymmetry - remove wireguard")
			return typhas, removeWireguardForBootstrapping(configParams, getNetlinkHandle, calicoClient, ipVersion)
		}

		return filtered, nil
	}

	return typhas, nil
}

// RemoveWireguardConditionallyOnBootstrap removes all wireguard configuration based on configuration conditions. This
// is called as a last resort after failing to connect to typha.
//
// The following wireguard configuration will be removed if HostEncryptionEnabled is true:
// - The wireguard public key
// - The wireguard device (which in turn will delete all wireguard routing rules).
//
// It is assumed that BootstrapAndFilterTyphaAddresses was called prior to calling this function.
func RemoveWireguardConditionallyOnBootstrap(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
	calicoClient clientv3.Interface,
) error {
	var errors []error

	errV4 := removeWireguardConditionallyOnBootstrapForIPVersion(configParams, getNetlinkHandle, calicoClient, 4)
	if errV4 != nil {
		errors = append(errors, fmt.Errorf("error removing IPv4 wireguard: %w", errV4))
	}

	errV6 := removeWireguardConditionallyOnBootstrapForIPVersion(configParams, getNetlinkHandle, calicoClient, 6)
	if errV6 != nil {
		errors = append(errors, fmt.Errorf("error removing IPv6 wireguard: %w", errV6))
	}

	if len(errors) > 0 {
		return fmt.Errorf("encountered errors during wireguard bootstrap: %v", errors)
	}

	return nil
}

func removeWireguardConditionallyOnBootstrapForIPVersion(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
	calicoClient clientv3.Interface,
	ipVersion uint8,
) error {
	logCtx := log.WithField("ipVersion", ipVersion)

	if ipVersion != 4 && ipVersion != 6 {
		return fmt.Errorf("unknown IP version: %d", ipVersion)
	}

	if (ipVersion == 4 && !configParams.WireguardEnabled) || (ipVersion == 6 && !configParams.WireguardEnabledV6) {
		logCtx.Debug("Wireguard is not enabled - configuration will have been removed in initial bootstrap")
		return nil
	}
	if !configParams.WireguardHostEncryptionEnabled {
		logCtx.Debug("No host encryption - not necessary to remove wireguard configuration")
		return nil
	}

	logCtx.Info("Removing wireguard device for bootstrapping")
	return removeWireguardForBootstrapping(configParams, getNetlinkHandle, calicoClient, ipVersion)
}

// filterTyphaEndpoints filters the supplied set of typha endpoints to the set where wireguard routing is most likely
// to succeed. Any errors encountered are swallowed and the associated peer is just included.
func filterTyphaEndpoints(
	configParams *config.Config,
	calicoClient clientv3.Interface,
	typhas []discovery.Typha,
	peers set.Set[string],
	ipVersion uint8,
) []discovery.Typha {
	logCtx := log.WithField("ipVersion", ipVersion)

	logCtx.Debugf("Filtering typha endpoints for wireguard: %v", typhas)

	var filtered []discovery.Typha

	for _, typha := range typhas {
		logCtx = logCtx.WithField("typhaAddr", typha.Addr)
		if typha.NodeName == nil {
			logCtx.Debug("Typha endpoint has no node information - include typha endpoint")
			filtered = append(filtered, typha)
			continue
		}

		typhaNodeName := *typha.NodeName
		logCtx = logCtx.WithField("typhaNodeName", typhaNodeName)
		if typhaNodeName == configParams.FelixHostname {
			// This is a local typha. We should always be able to connect.
			logCtx.Info("Typha endpoint is local - include typha endpoint")
			filtered = append(filtered, typha)
			continue
		}

		// Get the public key configured for the typha node. We use this to check if we have a matching key in our
		// kernel wireguard routing. Since we know we have a published key any remote node with a key will in theory
		// route to us via wireguard - so if we do not have a wireguard route to this node then there is no point in
		// attempting to connect to this node. That said, it is better to include too many nodes, so fail fast when
		// getting querying the node.
		typhaNodeKey, err := getPublicKeyForNode(logCtx, typhaNodeName, calicoClient, bootstrapMaxRetriesFailFast, ipVersion)
		if err != nil {
			// If we were unable to determine the public key then just include the endpoint.
			logCtx.WithError(err).Info("Unable to determine public key for node")
			filtered = append(filtered, typha)
			continue
		}
		logCtx = logCtx.WithField("typhaNodeKey", typhaNodeKey)

		if typhaNodeKey == "" {
			// There is no key configured and we don't have it in our kernel routing table. Include this typha.
			logCtx.Info("Typha node does not have a wireguard key and not in kernel - include typha endpoint")
			filtered = append(filtered, typha)
		} else if peers.Contains(typhaNodeKey) {
			// The public key on the typha node is configured in the local routing table. Include this typha.
			logCtx.Debug("Typha node has a wireguard key that is in the local wireguard routing table - include typha endpoint")
			filtered = append(filtered, typha)
		} else {
			// The public key on the typha node is not configured in the local routing table. There is no point in
			// including this typha because routing will not work and we'll take longer to find a working typha.
			logCtx.Warning("Typha node has wireguard key that is not in the local wireguard routing table - exclude typha endpoint")
		}
	}

	logCtx.Infof("Filtered typha endpoints: %v", filtered)

	return filtered
}

// removeWireguardForBootstrapping unconditionally removes all wireguard configuration. This includes:
// - The wireguard public key
// - The wireguard device (which in turn will delete all wireguard routing rules).
func removeWireguardForBootstrapping(
	configParams *config.Config,
	getNetlinkHandle func() (netlinkshim.Interface, error),
	calicoClient clientv3.Interface,
	ipVersion uint8,
) error {
	var errors []error
	// Remove all wireguard configuration that we can.
	if err := removeWireguardDevice(configParams, getNetlinkHandle, ipVersion); err != nil {
		errors = append(errors, fmt.Errorf("cannot remove wireguard device: %w", err))
	}
	if err2 := removeWireguardPublicKey(configParams.FelixHostname, calicoClient, ipVersion); err2 != nil {
		errors = append(errors, fmt.Errorf("cannot remove wireguard public key: %w", err2))
	}
	if len(errors) > 0 {
		return fmt.Errorf("encountered errors during wireguard device bootstrap: %v", errors)
	}

	return nil
}

// getPublicKeyForNode returns the configured wireguard public key for a given node.
func getPublicKeyForNode(logCtx *log.Entry, nodeName string, calicoClient clientv3.Interface, maxRetries int, ipVersion uint8) (string, error) {
	expBackoffMgr := wait.NewExponentialBackoffManager(
		bootstrapBackoffDuration,
		bootstrapBackoffMax,
		time.Minute,
		bootstrapBackoffExpFactor,
		bootstrapJitter,
		clock.RealClock{},
	)
	if ipVersion != 4 && ipVersion != 6 {
		return "", fmt.Errorf("unknown IP version: %d", ipVersion)
	}

	defer expBackoffMgr.Backoff().Stop()

	var err error
	var node *apiv3.Node
	for r := 0; r < maxRetries; r++ {
		cxt, cancel := context.WithTimeout(context.Background(), boostrapK8sClientTimeout)
		node, err = calicoClient.Nodes().Get(cxt, nodeName, options.GetOptions{})
		cancel()
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			// If the node does not exist then it's not going to have a wireguard public key configured.
			logCtx.Info("Node does not exist - no published wireguard key")
			return "", nil
		} else if err != nil {
			logCtx.WithError(err).Warn("Couldn't fetch node config from datastore, retrying")
			<-expBackoffMgr.Backoff().C() // safe to block here as we're not dependent on other threads
			continue
		}

		key := node.Status.WireguardPublicKey
		if ipVersion == 6 {
			key = node.Status.WireguardPublicKeyV6
		}

		return key, nil
	}

	return "", fmt.Errorf("couldn't determine public key configured for node after %d retries: %v", maxRetries, err)
}

// getWireguardDeviceInfo attempts to fetch the current wireguard state from the kernel:
// - Public key
// - Set of peer public keys
func getWireguardDeviceInfo(
	logCtx *log.Entry, wgIfaceName string, getWireguardHandle func() (netlinkshim.Wireguard, error),
) (string, set.Set[string]) {
	wg, err := getWireguardHandle()
	if err != nil {
		logCtx.Info("Couldn't acquire wireguard handle")
		return "", nil
	}
	defer func() {
		if err = wg.Close(); err != nil {
			logCtx.WithError(err).Info("Couldn't close wireguard handle")
		}
	}()

	dev, err := wg.DeviceByName(wgIfaceName)
	if err != nil {
		logCtx.WithError(err).Info("Couldn't find wireguard device, assuming no wireguard config")
		return "", nil
	}

	if dev.PublicKey == zeroKey {
		// No public key on device - treat as no config.
		logCtx.Info("No public key configured on device")
		return "", nil
	}

	// Construct the set of peer public keys.
	peers := set.New[string]()
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
	ipVersion uint8,
) error {
	wgDeviceName := configParams.WireguardInterfaceName
	if ipVersion == 6 {
		wgDeviceName = configParams.WireguardInterfaceNameV6
	} else if ipVersion != 4 {
		return fmt.Errorf("unknown IP version: %d", ipVersion)
	}
	nodeName := configParams.FelixHostname

	logCtx := log.WithFields(log.Fields{
		"ipVersion": ipVersion,
		"iface":     wgDeviceName,
		"nodeName":  nodeName,
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
		if err = removeDevice(logCtx, wgDeviceName, handle); err != nil {
			<-expBackoffMgr.Backoff().C()
			continue
		}
		return nil
	}

	return fmt.Errorf("couldn't remove wireguard device after %d retries: %v", bootstrapMaxRetries, err)
}

// removeWireguardPublicKey removes the public key from the node.
func removeWireguardPublicKey(
	nodeName string,
	calicoClient clientv3.Interface,
	ipVersion uint8,
) error {
	logCtx := log.WithFields(log.Fields{
		"ipVersion": ipVersion,
		"nodeName":  nodeName,
	})

	logCtx.Debug("Removing wireguard public key")

	if ipVersion != 4 && ipVersion != 6 {
		return fmt.Errorf("unknown IP version: %d", ipVersion)
	}

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
			// If the node does not exist then it's not going to have a wireguard public key configured.
			logCtx.Info("Node does not exist - no published wireguard key to remove")
			return nil
		} else if err != nil {
			logCtx.WithError(err).Warn("Couldn't fetch node config from datastore, retrying")
			<-expBackoffMgr.Backoff().C() // safe to block here as we're not dependent on other threads
			continue
		}

		// if there is any config mismatch, wipe the datastore's publickey (forces peers to send unencrypted traffic)
		if ipVersion == 4 && thisNode.Status.WireguardPublicKey != "" || ipVersion == 6 && thisNode.Status.WireguardPublicKeyV6 != "" {
			logCtx.Info("Wireguard key set on node - removing")
			switch ipVersion {
			case 4:
				thisNode.Status.WireguardPublicKey = ""
			case 6:
				thisNode.Status.WireguardPublicKeyV6 = ""
			}
			cxt, cancel = context.WithTimeout(context.Background(), boostrapK8sClientTimeout)
			_, err = calicoClient.Nodes().Update(cxt, thisNode, options.SetOptions{})
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

// removeDevice removes the named link.
func removeDevice(logCtx *log.Entry, name string, netlinkClient netlinkshim.Interface) error {
	link, err := netlinkClient.LinkByName(name)
	if err == nil {
		logCtx.Info("Deleting device")
		if err := netlinkClient.LinkDel(link); err != nil {
			logCtx.WithError(err).Error("Error deleting device")
			return err
		}
		logCtx.Info("Deleted wireguard device")
	} else if netlinkshim.IsNotExist(err) {
		logCtx.Debug("Device does not exist")
	} else if err != nil {
		logCtx.WithError(err).Error("Unable to determine if device exists")
		return err
	}
	return nil
}
