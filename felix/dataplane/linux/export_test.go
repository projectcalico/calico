// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// The following accessors expose otherwise-unexported dataplane state to tests
// in the external intdataplane_test package, without widening the real API.

func (d *InternalDataplane) VXLANManagerActive() bool {
	return d.vxlanManager != nil
}

func (d *InternalDataplane) VXLANManagerV6Active() bool {
	return d.vxlanManagerV6 != nil
}

func (d *InternalDataplane) IPIPManagerActive() bool {
	return d.ipipManager != nil
}

func (d *InternalDataplane) NoEncapManagerActive() bool {
	return d.noEncapManager != nil
}

func (d *InternalDataplane) NoEncapManagerV6Active() bool {
	return d.noEncapManagerV6 != nil
}

// The WireGuard managers are always registered (so they can tidy up state left
// over from a previous configuration); these accessors report whether WireGuard
// is actually enabled for programming.
func (d *InternalDataplane) WireguardManagerActive() bool {
	return d.wireguardManager != nil
}

func (d *InternalDataplane) WireguardEnabled() bool {
	return d.wireguardManager != nil && d.wireguardManager.wireguardRouteTable.Enabled()
}

func (d *InternalDataplane) WireguardEnabledV6() bool {
	return d.wireguardManagerV6 != nil && d.wireguardManagerV6.wireguardRouteTable.Enabled()
}
