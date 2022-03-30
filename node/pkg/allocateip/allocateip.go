// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
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

package allocateip

import (
	"context"
	"fmt"
	gnet "net"
	"os"
	"reflect"
	"time"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/tunnelipsyncer"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/node/buildinfo"
	"github.com/projectcalico/calico/node/pkg/calicoclient"
	"github.com/projectcalico/calico/typha/pkg/syncclientutils"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// This file contains the main processing and common logic for assigning tunnel addresses,
// used by calico/node to set the host's tunnel address if IPIP or VXLAN is enabled on the pool or
// wireguard is enabled on the node.
//
// It will assign an address if there are any available, and remove any tunnel addresses
// that are configured and should no longer be.

// Run runs the tunnel ip allocator. If done is nil, it runs in single-shot mode. If non-nil, it runs in daemon mode
// performing a reconciliation when IP pool or node configuration changes that may impact the allocations.
func Run(done <-chan struct{}) {
	// This binary is only ever invoked _after_ the
	// startup binary has been invoked and the modified environments have
	// been sourced.  Therefore, the NODENAME environment will always be
	// set at this point.
	nodename := os.Getenv("NODENAME")
	if nodename == "" {
		log.Panic("NODENAME environment is not set")
	}

	// Load the client config from environment.
	cfg, c := calicoclient.CreateClient()

	run(nodename, cfg, c, done)
}

func run(nodename string, cfg *apiconfig.CalicoAPIConfig, c client.Interface, done <-chan struct{}) {
	// If configured to use host-local IPAM, there is no need to configure tunnel addresses as they use the
	// first IP of the pod CIDR - this is handled in the k8s backend code in libcalico-go.
	if cfg.Spec.K8sUsePodCIDR {
		log.Debug("Using host-local IPAM, no need to allocate a tunnel IP")
		if done != nil {
			// If a done channel is specified, only exit when this is closed.
			<-done
		}
		return
	}

	if done == nil {
		// Running in single shot mode, so assign addresses and exit.
		reconcileTunnelAddrs(nodename, cfg, c)
		return
	}

	// This is running as a daemon. Create a long-running reconciler.
	r := &reconciler{
		nodename: nodename,
		cfg:      cfg,
		client:   c,
		ch:       make(chan struct{}),
		data:     make(map[string]interface{}),
	}

	// Either create a typha syncclient or a local syncer depending on configuration. This calls back into the
	// reconciler to trigger updates when necessary.

	// Read Typha settings from the environment.
	// When Typha is in use, there will already be variables prefixed with FELIX_, so it's
	// convenient if we honor those as well as the CALICO variables.
	typhaConfig := syncclientutils.ReadTyphaConfig([]string{"FELIX_", "CALICO_"})
	if syncclientutils.MustStartSyncerClientIfTyphaConfigured(
		&typhaConfig, syncproto.SyncerTypeTunnelIPAllocation,
		buildinfo.GitVersion, nodename, fmt.Sprintf("tunnel-ip-allocation %s", buildinfo.GitVersion),
		r,
	) {
		log.Debug("Using typha syncclient")
	} else {
		// Use the syncer locally.
		log.Debug("Using local syncer")
		syncer := tunnelipsyncer.New(c.(backendClientAccessor).Backend(), r, nodename)
		syncer.Start()
	}

	// Run the reconciler.
	r.run(done)
}

// reconciler watches IPPool and Node configuration and triggers a reconciliation of the Tunnel IP addresses whenever
// it spots a configuration change that may impact IP selection.
type reconciler struct {
	nodename string
	cfg      *apiconfig.CalicoAPIConfig
	client   client.Interface
	ch       chan struct{}
	data     map[string]interface{}
	inSync   bool
}

// run is the main reconciliation loop, it loops until done.
func (r reconciler) run(done <-chan struct{}) {
	// Loop forever, updating whenever we get a kick. The first kick will happen as soon as the syncer is in sync.
	for {
		select {
		case <-r.ch:
			// Received an update that requires reconciliation.  If the reconciliation fails it will cause the daemon
			// to exit this is fine - it will be restarted, and the syncer will trigger a reconciliation when in-sync
			// again.
			reconcileTunnelAddrs(r.nodename, r.cfg, r.client)
		case <-done:
			return
		}
	}
}

// OnStatusUpdated handles the syncer status callback method.
func (r *reconciler) OnStatusUpdated(status bapi.SyncStatus) {
	if status == bapi.InSync {
		// We are in-sync, trigger an initial scan/update of the IP addresses.
		r.inSync = true
		r.ch <- struct{}{}
	}
}

// OnUpdates handles the syncer resource updates.
func (r *reconciler) OnUpdates(updates []bapi.Update) {
	var updated bool
	for _, u := range updates {
		switch u.UpdateType {
		case bapi.UpdateTypeKVDeleted:
			// Resource is deleted. If this resource is in our cache then trigger an update.
			if _, ok := r.data[u.Key.String()]; ok {
				updated = true
			}
			delete(r.data, u.Key.String())
		case bapi.UpdateTypeKVNew, bapi.UpdateTypeKVUpdated:
			// Resource is created or updated. Depending on the resource, we extract and cache the relevant data that
			// we are monitoring. If the data has changed then trigger an update.
			var data interface{}
			switch v := u.Value.(type) {
			case *model.IPPool:
				// For pools just track the whole data.
				log.Debugf("Updated pool resource: %s", u.Key)
				data = v
			case *libapi.Node:
				// For nodes, we only care about our own node, *and* we only care about the wireguard public key.
				if v.Name != r.nodename {
					continue
				}
				log.Debugf("Updated node resource: %s", u.Key)
				data = v.Status.WireguardPublicKey
			default:
				// We got an update for an unexpected resource type. Rather than ignore, just treat as updated so that
				// we reconcile the addresses.
				log.Warningf("Unexpected resource update: %s", u.Key)
				updated = true
				continue
			}

			if existing, ok := r.data[u.Key.String()]; !ok || !reflect.DeepEqual(existing, data) {
				// Entry is new or associated data is modified. In either case update the data and flag as updated.
				log.Debug("Stored data has been modified - trigger reconciliation")
				updated = true
				r.data[u.Key.String()] = data
			}
		}
	}

	if updated && r.inSync {
		// We have updated data. Trigger a reconciliation, but don't block if there is already an update pending.
		select {
		case r.ch <- struct{}{}:
		default:
		}
	}
}

// reconcileTunnelAddrs performs a single shot update of the tunnel IP allocations.
func reconcileTunnelAddrs(nodename string, cfg *apiconfig.CalicoAPIConfig, c client.Interface) {
	ctx := context.Background()
	// Get node resource for given nodename.
	node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
	if err != nil {
		log.WithError(err).Fatalf("failed to fetch node resource '%s'", nodename)
	}

	// Get list of ip pools
	ipPoolList, err := c.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Fatal("Unable to query IP pool configuration")
	}

	// If wireguard is enabled then allocate an IP for the wireguard device. We do this for all deployment types even
	// when pod CIDRs are not managed by Calico.
	if cidrs := determineEnabledPoolCIDRs(*node, *ipPoolList, ipam.AttributeTypeWireguard); len(cidrs) > 0 {
		ensureHostTunnelAddress(ctx, c, nodename, cidrs, ipam.AttributeTypeWireguard)
	} else {
		removeHostTunnelAddr(ctx, c, nodename, ipam.AttributeTypeWireguard)
	}

	// Query the IPIP enabled pools and either configure the tunnel
	// address, or remove it.
	if cidrs := determineEnabledPoolCIDRs(*node, *ipPoolList, ipam.AttributeTypeIPIP); len(cidrs) > 0 {
		ensureHostTunnelAddress(ctx, c, nodename, cidrs, ipam.AttributeTypeIPIP)
	} else {
		removeHostTunnelAddr(ctx, c, nodename, ipam.AttributeTypeIPIP)
	}

	// Query the VXLAN enabled pools and either configure the tunnel
	// address, or remove it.
	if cidrs := determineEnabledPoolCIDRs(*node, *ipPoolList, ipam.AttributeTypeVXLAN); len(cidrs) > 0 {
		ensureHostTunnelAddress(ctx, c, nodename, cidrs, ipam.AttributeTypeVXLAN)
	} else {
		removeHostTunnelAddr(ctx, c, nodename, ipam.AttributeTypeVXLAN)
	}
}

func ensureHostTunnelAddress(ctx context.Context, c client.Interface, nodename string, cidrs []net.IPNet, attrType string) {
	logCtx := getLogger(attrType)
	logCtx.WithField("node", nodename).Debug("Ensure tunnel address is set")

	// Get the currently configured address.
	node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
	if err != nil {
		logCtx.WithError(err).Fatalf("Unable to retrieve tunnel address. Error getting node '%s'", nodename)
	}

	// Get the address and ipam attribute string
	var addr string
	switch attrType {
	case ipam.AttributeTypeVXLAN:
		addr = node.Spec.IPv4VXLANTunnelAddr
	case ipam.AttributeTypeIPIP:
		if node.Spec.BGP != nil {
			addr = node.Spec.BGP.IPv4IPIPTunnelAddr
		}
	case ipam.AttributeTypeWireguard:
		if node.Spec.Wireguard != nil {
			addr = node.Spec.Wireguard.InterfaceIPv4Address
		}
	}

	// Work out if we need to assign a tunnel address.
	// In most cases we should not release current address and should assign new one.
	release := false
	assign := true
	if addr == "" {
		// The tunnel has no IP address assigned, assign one.
		logCtx.Info("Assign a new tunnel address")

		// Defensively release any IP addresses with this handle. This covers a theoretical case
		// where the node object has lost its reference to its IP, but the allocation still exists
		// in IPAM. For example, if the node object was manually edited.
		release = true
	} else {
		// Go ahead checking status of current address.
		ipAddr := gnet.ParseIP(addr)
		if ipAddr == nil {
			logCtx.WithError(err).Fatalf("Failed to parse the CIDR '%s'", addr)
		}

		// Check if we got correct assignment attributes.
		attr, handle, err := c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: ipAddr})
		if err == nil {
			if attr[ipam.AttributeType] == attrType && attr[ipam.AttributeNode] == nodename {
				// The tunnel address is still assigned to this node, but is it in the correct pool this time?
				if !isIpInPool(addr, cidrs) {
					// Wrong pool, release this address.
					logCtx.WithField("currentAddr", addr).Info("Current address is not in a valid pool, release it and reassign")
					release = true
				} else {
					// Correct pool, keep this address.
					logCtx.WithField("currentAddr", addr).Info("Current address is still valid, do nothing")
					assign = false
				}
			} else if len(attr) == 0 {
				// No attributes means that this is an old address, assigned by code that didn't use
				// allocation attributes. It might be a pod address, or it might be a node tunnel
				// address. The only way to tell is by the existence of a handle, since workload
				// addresses have always used a handle, whereas tunnel addresses didn't start
				// using handles until the same time as they got allocation attributes.
				if handle != nil {
					// Handle exists, so this address belongs to a workload. We need to assign
					// a new one for the node, but we shouldn't clean up the old address.
					logCtx.WithField("currentAddr", addr).Info("Current address is occupied, assign a new one")
				} else {
					// Handle does not exist. This is just an old tunnel address that comes from
					// a time before we used handles and allocation attributes. Attempt to
					// reassign the same address, but now with metadata. It's possible that someone
					// else takes the address while we do this, in which case we'll just
					// need to assign a new address.
					if err := correctAllocationWithHandle(ctx, c, addr, nodename, attrType); err != nil {
						if _, ok := err.(cerrors.ErrorResourceAlreadyExists); !ok {
							// Unknown error attempting to allocate the address. Exit.
							logCtx.WithError(err).Fatal("Error correcting tunnel IP allocation")
						}

						// The address was taken by someone else. We need to assign a new one.
						logCtx.WithError(err).Warn("Failed to correct missing attributes, will assign a new address")
					} else {
						// We corrected the address, we can just return.
						logCtx.Info("Updated tunnel address with allocation attributes")
						return
					}
				}
			} else {
				// The allocation has attributes, but doesn't belong to us. Assign a new one.
				logCtx.WithField("currentAddr", addr).Info("Current address is occupied, assign a new one")
			}
		} else if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			// The tunnel address is not assigned, reassign it.
			logCtx.WithField("currentAddr", addr).Info("Current address is not assigned, assign a new one")

			// Defensively release any IP addresses with this handle. This covers a theoretical case
			// where the node object has lost its reference to its correct IP, but the allocation still exists
			// in IPAM. For example, if the node object was manually edited.
			release = true
		} else {
			// Failed to get assignment attributes, datastore connection issues possible, panic
			logCtx.WithError(err).Panicf("Failed to get assignment attributes for CIDR '%s'", addr)
		}
	}

	if release {
		logCtx.WithField("IP", addr).Info("Release any old tunnel addresses")
		handle, _ := generateHandleAndAttributes(nodename, attrType)
		if err := c.IPAM().ReleaseByHandle(ctx, handle); err != nil {
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
				logCtx.WithError(err).Fatal("Failed to release old addresses")
			}
			// No existing allocations for this node.
		}
	}

	if assign {
		logCtx.WithField("IP", addr).Info("Assign new tunnel address")
		assignHostTunnelAddr(ctx, c, nodename, cidrs, attrType)
	}
}

func correctAllocationWithHandle(ctx context.Context, c client.Interface, addr, nodename string, attrType string) error {
	ipAddr := net.ParseIP(addr)
	if ipAddr == nil {
		log.Fatalf("Failed to parse node tunnel address '%s'", addr)
		return nil
	}

	// Release the old allocation.
	_, err := c.IPAM().ReleaseIPs(ctx, ipam.ReleaseOptions{Address: ipAddr.String()})
	if err != nil {
		// If we fail to release the old allocation, we shouldn't continue any further. Just exit.
		log.WithField("IP", ipAddr.String()).WithError(err).Fatal("Error releasing address")
	}

	// Attempt to re-assign the same address, but with a handle this time.
	handle, attrs := generateHandleAndAttributes(nodename, attrType)
	args := ipam.AssignIPArgs{
		IP:       *ipAddr,
		HandleID: &handle,
		Attrs:    attrs,
		Hostname: nodename,
	}

	// If we fail to allocate the same IP, return an error. We'll just
	// have to allocate a new one.
	return c.IPAM().AssignIP(ctx, args)
}

func generateHandleAndAttributes(nodename string, attrType string) (string, map[string]string) {
	attrs := map[string]string{ipam.AttributeNode: nodename}
	var handle string
	switch attrType {
	case ipam.AttributeTypeVXLAN:
		handle = fmt.Sprintf("vxlan-tunnel-addr-%s", nodename)
	case ipam.AttributeTypeIPIP:
		handle = fmt.Sprintf("ipip-tunnel-addr-%s", nodename)
	case ipam.AttributeTypeWireguard:
		handle = fmt.Sprintf("wireguard-tunnel-addr-%s", nodename)
	}
	attrs[ipam.AttributeType] = attrType
	return handle, attrs
}

// assignHostTunnelAddr claims an IP address from the first pool
// with some space. Stores the result in the host's config as its tunnel
// address. It will assign a VXLAN address if vxlan is true, otherwise an IPIP address.
func assignHostTunnelAddr(ctx context.Context, c client.Interface, nodename string, cidrs []net.IPNet, attrType string) {
	// Build attributes and handle for this allocation.
	handle, attrs := generateHandleAndAttributes(nodename, attrType)
	logCtx := getLogger(attrType)

	args := ipam.AutoAssignArgs{
		Num4:        1,
		Num6:        0,
		HandleID:    &handle,
		Attrs:       attrs,
		Hostname:    nodename,
		IPv4Pools:   cidrs,
		IntendedUse: api.IPPoolAllowedUseTunnel,
	}

	v4Assignments, _, err := c.IPAM().AutoAssign(ctx, args)
	if err != nil {
		logCtx.WithError(err).Fatal("Unable to autoassign an address")
	}

	if err := v4Assignments.PartialFulfillmentError(); err != nil {
		logCtx.WithError(err).Fatal("Unable to autoassign an address")
	}

	// Update the node object with the assigned address.
	ip := v4Assignments.IPs[0].IP.String()
	if err = updateNodeWithAddress(ctx, c, nodename, ip, attrType); err != nil {
		// We hit an error, so release the IP address before exiting.
		err := c.IPAM().ReleaseByHandle(ctx, handle)
		if err != nil {
			logCtx.WithError(err).WithField("IP", ip).Errorf("Error releasing IP address on failure")
		}

		// Log the error and exit with exit code 1.
		logCtx.WithError(err).WithField("IP", ip).Fatal("Unable to set tunnel address")
	}

	logCtx.WithField("IP", ip).Info("Assigned tunnel address to node")
}

func updateNodeWithAddress(ctx context.Context, c client.Interface, nodename string, addr string, attrType string) error {
	// If the update fails with ResourceConflict error then retry 5 times with 1 second delay before failing.
	for i := 0; i < 5; i++ {
		node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
		if err != nil {
			return err
		}

		switch attrType {
		case ipam.AttributeTypeVXLAN:
			node.Spec.IPv4VXLANTunnelAddr = addr
		case ipam.AttributeTypeIPIP:
			if node.Spec.BGP == nil {
				node.Spec.BGP = &libapi.NodeBGPSpec{}
			}
			node.Spec.BGP.IPv4IPIPTunnelAddr = addr
		case ipam.AttributeTypeWireguard:
			if node.Spec.Wireguard == nil {
				node.Spec.Wireguard = &libapi.NodeWireguardSpec{}
			}
			node.Spec.Wireguard.InterfaceIPv4Address = addr
		}

		_, err = c.Nodes().Update(ctx, node, options.SetOptions{})
		if _, ok := err.(cerrors.ErrorResourceUpdateConflict); ok {
			// Wait for a second and try again if there was a conflict during the resource update.
			log.WithField("node", node.Name).WithError(err).Info("Error updating node, retrying.")
			time.Sleep(1 * time.Second)
			continue
		}

		return nil
	}
	return fmt.Errorf("Too many retries attempting to update node with tunnel address")
}

// removeHostTunnelAddr removes any existing IP address for this host's
// tunnel device and releases the IP from IPAM.  If no IP is assigned this function
// is a no-op.
func removeHostTunnelAddr(ctx context.Context, c client.Interface, nodename string, attrType string) {
	var updateError error
	logCtx := getLogger(attrType)
	logCtx.WithField("node", nodename).Debug("Remove tunnel addresses")

	// If the update fails with ResourceConflict error then retry 5 times with 1 second delay before failing.
	for i := 0; i < 5; i++ {
		node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
		if err != nil {
			logCtx.WithError(err).Fatalf("Unable to retrieve tunnel address for cleanup. Error getting node '%s'", nodename)
		}

		// Find out the currently assigned address and remove it from the node.
		var ipAddrStr string
		var ipAddr *net.IP
		switch attrType {
		case ipam.AttributeTypeVXLAN:
			ipAddrStr = node.Spec.IPv4VXLANTunnelAddr
			node.Spec.IPv4VXLANTunnelAddr = ""
		case ipam.AttributeTypeIPIP:
			if node.Spec.BGP != nil {
				ipAddrStr = node.Spec.BGP.IPv4IPIPTunnelAddr
				node.Spec.BGP.IPv4IPIPTunnelAddr = ""

				// If removing the tunnel address causes the BGP spec to be empty, then nil it out.
				// libcalico asserts that if a BGP spec is present, that it not be empty.
				if reflect.DeepEqual(*node.Spec.BGP, libapi.NodeBGPSpec{}) {
					logCtx.Debug("BGP spec is now empty, setting to nil")
					node.Spec.BGP = nil
				}
			}
		case ipam.AttributeTypeWireguard:
			if node.Spec.Wireguard != nil {
				ipAddrStr = node.Spec.Wireguard.InterfaceIPv4Address
				node.Spec.Wireguard.InterfaceIPv4Address = ""

				if reflect.DeepEqual(*node.Spec.Wireguard, libapi.NodeWireguardSpec{}) {
					logCtx.Debug("Wireguard spec is now empty, setting to nil")
					node.Spec.Wireguard = nil
				}
			}
		}

		if ipAddrStr != "" {
			ipAddr = net.ParseIP(ipAddrStr)
		}

		// Release tunnel IP address(es) for the node.
		handle, _ := generateHandleAndAttributes(nodename, attrType)
		if err := c.IPAM().ReleaseByHandle(ctx, handle); err != nil {
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
				// Unknown error releasing the address.
				logCtx.WithError(err).WithFields(log.Fields{
					"IP":     ipAddrStr,
					"Handle": handle,
				}).Fatal("Error releasing address by handle")
			}

			// Resource does not exist. This can occur in a few scenarios:
			//
			// 1. The IP is genuinely not allocated, and there's nothing for us to do.
			// 2. The IP pre-dates the use of handles in this code, and so the handle doesn't exist.
			// 3. We have gotten into an invalid state where the handle has been deleted but the IP is still allocated.
			//
			// For scenario #1, there is no more work to do.
			// We can determine if we're encountering scenario #2 or #3 by inspecting the allocation's attributes.
			// For scenario #2, we expect no attributes and no handle to be stored with the allocation.
			// For scenario #3, we expect a handle in the attributes and it should match the expected value.
			if ipAddr != nil {
				// There are no addresses with this handle. If there is an IP configured on the node, check to see if it
				// belongs to us. If it has no handle and no attributes, then we can pretty confidently
				// say that it belongs to us rather than a pod and should be cleaned up.
				logCtx.WithField("handle", handle).Info("No IPs with handle, release exact IP")
				attr, storedHandle, err := c.IPAM().GetAssignmentAttributes(ctx, *ipAddr)
				if err != nil {
					if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
						logCtx.WithError(err).Fatal("Failed to query attributes")
					}
					// Scenario #1: The allocation actually doesn't exist, we don't have anything to do.
				} else if len(attr) == 0 && storedHandle == nil {
					// Scenario #2: The allocation exists, but has no handle whatsoever.
					// This is an ancient allocation and can be released.
					if _, err := c.IPAM().ReleaseIPs(ctx, ipam.ReleaseOptions{Address: ipAddr.String()}); err != nil {
						logCtx.WithError(err).WithField("IP", ipAddr.String()).Fatal("Error releasing address from IPAM")
					}
				} else if storedHandle != nil && *storedHandle == handle {
					// Scenario #3: The allocation exists, has a handle, and it matches the one we expect.
					// This means the handle object itself was wrongfully deleted. We can clean it up
					// by releasing the IP directly with both address and handle specified.
					if _, err := c.IPAM().ReleaseIPs(ctx, ipam.ReleaseOptions{Address: ipAddr.String(), Handle: handle}); err != nil {
						logCtx.WithError(err).WithField("IP", ipAddr.String()).Fatal("Error releasing address from IPAM")
					}
				} else {
					// The final scenario: the IP on the node is allocated, but it is allocated to some other handle.
					// It doesn't belong to us. We can't do anything here but it's worth logging.
					fields := log.Fields{"attributes": attr, "IP": ipAddr.String()}
					logCtx.WithFields(fields).Warnf("IP address has been reused by something else")
				}
			}
		}

		// Update the node object.
		_, updateError = c.Nodes().Update(ctx, node, options.SetOptions{})
		if _, ok := updateError.(cerrors.ErrorResourceUpdateConflict); ok {
			// Wait for a second and try again if there was a conflict during the resource update.
			logCtx.Infof("Error updating node %s: %s. Retrying.", node.Name, err)
			time.Sleep(1 * time.Second)
			continue
		}

		break
	}

	// Check to see if there was still an error after the retry loop,
	// and log and exit if there was an error.
	if updateError != nil {
		// We hit an error, so release the IP address before exiting.
		// Log the error and exit with exit code 1.
		logCtx.WithError(updateError).Fatal("Unable to remove tunnel address")
	}
}

// determineEnabledPools returns all enabled pools. If vxlan is true, then it will only return VXLAN pools. Otherwise
// it will only return IPIP enabled pools.
func determineEnabledPoolCIDRs(node libapi.Node, ipPoolList api.IPPoolList, attrType string) []net.IPNet {
	// For wireguard, return no valid pools if the wireguard public key has not been set. Only once wireguard has been
	// enabled *and* the wireguard device has been initialized do we require an IP address to be configured.
	if attrType == ipam.AttributeTypeWireguard && node.Status.WireguardPublicKey == "" {
		log.Debugf("Wireguard is not running on node %s", node.Name)
		return nil
	}

	var cidrs []net.IPNet
	for _, ipPool := range ipPoolList.Items {
		_, poolCidr, err := net.ParseCIDR(ipPool.Spec.CIDR)
		if err != nil {
			log.WithError(err).Fatalf("Failed to parse CIDR '%s' for IPPool '%s'", ipPool.Spec.CIDR, ipPool.Name)
		}

		// Check if IP pool selects the node
		if selects, err := ipam.SelectsNode(ipPool, node); err != nil {
			log.WithError(err).Errorf("Failed to compare nodeSelector '%s' for IPPool '%s', skipping", ipPool.Spec.NodeSelector, ipPool.Name)
			continue
		} else if !selects {
			log.Debugf("IPPool '%s' does not select Node '%s'", ipPool.Name, node.Name)
			continue
		}

		// Check if desired encap is enabled in the IP pool, the IP pool is not disabled, and it is IPv4 pool since we
		// don't support encap with IPv6.
		switch attrType {
		case ipam.AttributeTypeVXLAN:
			if (ipPool.Spec.VXLANMode == api.VXLANModeAlways || ipPool.Spec.VXLANMode == api.VXLANModeCrossSubnet) && !ipPool.Spec.Disabled && poolCidr.Version() == 4 {
				cidrs = append(cidrs, *poolCidr)
			}
		case ipam.AttributeTypeIPIP:
			// Check if IPIP is enabled in the IP pool, the IP pool is not disabled, and it is IPv4 pool since we don't support IPIP with IPv6.
			if (ipPool.Spec.IPIPMode == api.IPIPModeCrossSubnet || ipPool.Spec.IPIPMode == api.IPIPModeAlways) && !ipPool.Spec.Disabled && poolCidr.Version() == 4 {
				cidrs = append(cidrs, *poolCidr)
			}
		case ipam.AttributeTypeWireguard:
			// Wireguard does not require a specific encap configuration on the pool.
			if !ipPool.Spec.Disabled && poolCidr.Version() == 4 {
				cidrs = append(cidrs, *poolCidr)
			}
		}
	}
	return cidrs
}

// isIpInPool returns if the IP address is in one of the supplied pools.
func isIpInPool(ipAddrStr string, cidrs []net.IPNet) bool {
	ipAddress := net.ParseIP(ipAddrStr)
	for _, cidr := range cidrs {
		if cidr.Contains(ipAddress.IP) {
			return true
		}
	}
	return false
}

func getLogger(attrType string) *log.Entry {
	switch attrType {
	case ipam.AttributeTypeVXLAN:
		return log.WithField("type", "vxlanTunnelAddress")
	case ipam.AttributeTypeIPIP:
		return log.WithField("type", "ipipTunnelAddress")
	case ipam.AttributeTypeWireguard:
		return log.WithField("type", "wireguardTunnelAddress")
	}
	return nil
}

// backendClientAccessor is an interface to access the backend client from the main v2 client.
type backendClientAccessor interface {
	Backend() bapi.Client
}
