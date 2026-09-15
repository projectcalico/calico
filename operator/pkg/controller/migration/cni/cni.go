// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package cni

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/types"
)

type NetworkComponents struct {
	ConfigName          string
	CalicoConfig        *CalicoConf
	HostLocalIPAMConfig *HostLocalIPAMConfig

	// other CNI plugins in the conflist.
	Plugins map[string]*libcni.NetworkConfig
}

// IPAMConfig represents the IP related network configuration.
// This nests Range because we initially only supported a single
// range directly, and wish to preserve backwards compatibility
type HostLocalIPAMConfig struct {
	*Range
	Name       string
	Type       string         `json:"type"`
	Routes     []*types.Route `json:"routes"`
	DataDir    string         `json:"dataDir"`
	ResolvConf string         `json:"resolvConf"`
	Ranges     []RangeSet     `json:"ranges"`
	IPArgs     []net.IP       `json:"-"` // Requested IPs from CNI_ARGS and args
}

type RangeSet []Range

type Range struct {
	RangeStart string `json:"rangeStart,omitempty"` // The first ip, inclusive
	RangeEnd   string `json:"rangeEnd,omitempty"`   // The last ip, inclusive
	Subnet     string `json:"subnet"`
	Gateway    net.IP `json:"gateway,omitempty"`
}

// Parse loads CNI config into the components for all other handlers to use.
// No verification is done here beyond checking for valid json.
// Calico CNI is parsed into the special Calico CNI data type.
// All other CNI types
func Parse(cniConfig string) (NetworkComponents, error) {
	c := NetworkComponents{}

	conflist, err := unmarshalCNIConfList(cniConfig)
	if err != nil {
		return c, fmt.Errorf("failed to parse CNI config: %w", err)
	}

	c.ConfigName = conflist.Name

	// convert to a map for simpler checks
	plugins := map[string]*libcni.NetworkConfig{}
	for _, plugin := range conflist.Plugins {
		if plugin.Network.Type == "calico" {
			if err := json.Unmarshal(plugin.Bytes, &c.CalicoConfig); err != nil {
				return c, fmt.Errorf("failed to parse calico cni config: %w", err)
			}
			if plugin.Network.IPAM.Type == "host-local" {
				// First load the IPAM json section so we can Unmarshal it below.
				// We load the IPAM as raw json so we can isolate it from the rest of the
				// CNI config.
				var raw struct {
					IPAM json.RawMessage `json:"ipam"`
				}
				if err := json.Unmarshal(plugin.Bytes, &raw); err != nil {
					return c, fmt.Errorf("failed to parse cni config for raw IPAM: %w", err)
				}

				// Use a Decoder so we can set DisallowUnknownFields so if there are
				// any unknown fields we will detect that.
				x := HostLocalIPAMConfig{}
				dec := json.NewDecoder(bytes.NewReader(raw.IPAM))
				dec.DisallowUnknownFields()
				if err := dec.Decode(&x); err != nil && err != io.EOF {
					return c, fmt.Errorf("failed to parse HostLocal IPAM config: %w", err)
				}
				c.HostLocalIPAMConfig = &x
			}
		} else {
			plugins[plugin.Network.Type] = plugin
		}
	}
	c.Plugins = plugins

	return c, nil
}

func unmarshalCNIConfList(cniConfig string) (*libcni.NetworkConfigList, error) {
	// unrendered CNI_NETWORK_CONFIG is often technically invalid json because it uses
	// __CNI_MTU__ as an integer, e.g. { "mtu": __CNI_MTU__ }
	// in such cases, replace it with a placeholder, so that we can json load it, and still
	// know that it should be substituted later during validation.
	cniConfig = strings.ReplaceAll(cniConfig, "__CNI_MTU__", "-1")

	// libcni v1.3.0 accepts a JSON object without a "plugins" key as an empty
	// conflist (returning success with len(Plugins) == 0) rather than an error,
	// so treat that case as if conflist parsing failed and fall through to
	// single-conf parsing.
	confList, err := libcni.ConfListFromBytes([]byte(cniConfig))
	if err == nil && len(confList.Plugins) > 0 {
		return confList, nil
	}

	// try parsing as a single item. The legacy single-conf format is deprecated
	// by the CNI spec but may still exist on clusters being migrated from older
	// Calico installations.
	conf, err := libcni.NetworkPluginConfFromBytes([]byte(cniConfig))
	if err != nil {
		return nil, err
	}

	return libcni.ConfListFromConf(conf) //nolint:staticcheck // no non-deprecated equivalent for wrapping a single-conf as a conflist
}
