// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
)

type noEncapManager struct {
	// Our dependencies.
	hostname  string
	ipVersion uint8
	routeMgr  *routeManager

	// Log context
	logCtx     *logrus.Entry
	opRecorder logutils.OpRecorder
}

func newNoEncapManager(
	mainRouteTable routetable.Interface,
	ipVersion uint8,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
) *noEncapManager {
	nlHandle, _ := netlinkshim.NewRealNetlink()
	return newNoEncapManagerWithSims(
		mainRouteTable,
		ipVersion,
		dpConfig,
		opRecorder,
		nlHandle,
	)
}

func newNoEncapManagerWithSims(
	mainRouteTable routetable.Interface,
	ipVersion uint8,
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	nlHandle netlinkHandle,
) *noEncapManager {

	if ipVersion != 4 {
		logrus.Errorf("NoEncap manager only supports IPv4")
		return nil
	}

	m := &noEncapManager{
		hostname:  dpConfig.Hostname,
		ipVersion: ipVersion,
		logCtx: logrus.WithFields(logrus.Fields{
			"ipVersion": ipVersion,
		}),
		opRecorder: opRecorder,
		routeMgr: newRouteManager(
			mainRouteTable,
			routetable.RouteClassNoEncap,
			routetable.RouteClassNoEncap,
			proto.IPPoolType_NO_ENCAP,
			"",
			ipVersion,
			0,
			dpConfig,
			opRecorder,
			nlHandle,
		),
	}

	m.routeMgr.setTunnelRouteFunc(m.tunnelRoute)
	m.routeMgr.triggerRouteUpdate()
	return m
}

func (m *noEncapManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.HostMetadataUpdate:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host update/create")
		if msg.Hostname == m.hostname {
			m.routeMgr.updateParentIfaceAddr(msg.Ipv4Addr)
		}
		m.routeMgr.triggerRouteUpdate()
	case *proto.HostMetadataRemove:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host removed")
		if msg.Hostname == m.hostname {
			m.routeMgr.updateParentIfaceAddr("")
		}
		m.routeMgr.triggerRouteUpdate()
	default:
		m.routeMgr.OnUpdate(msg)
	}
}

func (m *noEncapManager) CompleteDeferredWork() error {
	return m.routeMgr.CompleteDeferredWork()
}

func (m *noEncapManager) tunnelRoute(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
	return nil
}

func (m *noEncapManager) monitorParentDevice(ctx context.Context, wait time.Duration, parentIfaceC chan string) {
	// NoEncap manager does not need to configure any interface. It expects the parent interface to be up and configured.
	// However, it needs to monitor the parent interface to update routes. For this, we can use route manager
	// keepDeviceInSync method without providing any device to configure.
	m.routeMgr.keepDeviceInSync(ctx, 0, false, wait, parentIfaceC, m.device)
}

func (m *noEncapManager) device(_ netlink.Link) (netlink.Link, string, error) {
	return nil, "", nil
}
