// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package netlinkshim

import (
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Wireguard is a shim interface for mocking linkClient calls to manage the wireguard key and peer configuration.
type Wireguard interface {
	Close() error
	DeviceByName(name string) (*wgtypes.Device, error)
	Devices() ([]*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}

func NewRealWireguard() (Wireguard, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &realWireguardClient{
		client: client,
	}, nil
}

func (c *realWireguardClient) Close() error {
	return c.client.Close()
}

func (c *realWireguardClient) Devices() ([]*wgtypes.Device, error) {
	return c.client.Devices()
}

func (c *realWireguardClient) DeviceByName(name string) (*wgtypes.Device, error) {
	return c.client.Device(name)
}

func (c *realWireguardClient) ConfigureDevice(name string, cfg wgtypes.Config) error {
	return c.client.ConfigureDevice(name, cfg)
}

type realWireguardClient struct {
	client *wgctrl.Client
}
