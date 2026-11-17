// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

package noencap

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/dataplane/linux/dpconfig"
	"github.com/projectcalico/calico/felix/dataplane/linux/route"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/lib/logrusr"
)

type Manager struct {
	// Our dependencies.
	hostname  string
	ipVersion uint8
	routeMgr  *route.Manager

	// Log context
	logCtx     *logrus.Entry
	opRecorder logrusr.OpRecorder
}

func NewManager(
	mainRouteTable routetable.Interface,
	ipVersion uint8,
	dpConfig dpconfig.Config,
	opRecorder logrusr.OpRecorder,
) *Manager {
	nlHandle, _ := netlinkshim.NewRealNetlink()
	return NewManagerWithShims(
		mainRouteTable,
		ipVersion,
		dpConfig,
		opRecorder,
		nlHandle,
	)
}

func NewManagerWithShims(
	mainRouteTable routetable.Interface,
	ipVersion uint8,
	dpConfig dpconfig.Config,
	opRecorder logrusr.OpRecorder,
	nlHandle netlinkshim.Interface,
) *Manager {

	m := &Manager{
		hostname:  dpConfig.Hostname,
		ipVersion: ipVersion,
		logCtx: logrus.WithFields(logrus.Fields{
			"ipVersion": ipVersion,
		}),
		opRecorder: opRecorder,
		routeMgr: route.NewManager(
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

	m.routeMgr.SetTunnelRouteFunc(m.tunnelRoute)
	m.routeMgr.TriggerRouteUpdate()
	return m
}

func (m *Manager) OnUpdate(protoBufMsg any) {
	switch msg := protoBufMsg.(type) {
	case *proto.HostMetadataUpdate:
		if msg.Hostname != m.hostname {
			break
		}
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host update/create")
		var addrStr string
		if m.ipVersion == 4 {
			addrStr = msg.Ipv4Addr
		} else {
			addrStr = msg.Ipv6Addr
		}
		m.routesNeedUpdate(addrStr)
	case *proto.HostMetadataRemove:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host removed")
		if msg.Hostname == m.hostname {
			m.routesNeedUpdate("")
		}
	default:
		m.routeMgr.OnUpdate(msg)
	}
}

func (m *Manager) routesNeedUpdate(parentAddr string) {
	m.routeMgr.UpdateParentIfaceAddr(parentAddr)
	m.routeMgr.TriggerRouteUpdate()
}

func (m *Manager) CompleteDeferredWork() error {
	return m.routeMgr.CompleteDeferredWork()
}

func (m *Manager) tunnelRoute(cidr ip.CIDR, r *proto.RouteUpdate) *routetable.Target {
	return nil
}

func (m *Manager) MonitorParentDevice(ctx context.Context, wait time.Duration, parentIfaceC chan string) {
	// NoEncap manager does not need to configure any interface. It expects the parent interface to be up and configured.
	// However, it needs to monitor the parent interface to update routes. For this, we can use route manager
	// keepDeviceInSync method without providing any device to configure.
	m.routeMgr.KeepDeviceInSync(ctx, 0, false, wait, parentIfaceC, m.device)
}

func (m *Manager) device(_ netlink.Link) (netlink.Link, string, error) {
	return nil, "", nil
}

// OnParentDeviceUpdate records the tunnel's parent device and reports whether it
// changed.
func (m *Manager) OnParentDeviceUpdate(name string) bool {
	return m.routeMgr.OnParentDeviceUpdate(name)
}
