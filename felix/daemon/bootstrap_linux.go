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

package daemon

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/wireguard"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/typha/pkg/discovery"
)

// bootstrapWireguard performs some start-up single shot bootstrapping of wireguard configuration.
func bootstrapWireguardAndFilterTyphaAddresses(
	configParams *config.Config, v3Client clientv3.Interface, typhas []discovery.Typha,
) ([]discovery.Typha, error) {
	log.Debug("bootstrapping wireguard host connectivity")
	return wireguard.BootstrapHostConnectivityAndFilterTyphaAddresses(
		configParams,
		netlinkshim.NewRealNetlink,
		netlinkshim.NewRealWireguard,
		v3Client,
		typhas,
	)
}

// bootstrapRemoveWireguard removes the local wireguard configuration to force unencrypted traffic. This is a last
// resort used when failing to connect to typha.
func bootstrapRemoveWireguard(configParams *config.Config, v3Client clientv3.Interface) error {
	log.Debug("bootstrapping wireguard host connectivity by removing wireguard config")
	return wireguard.RemoveWireguardConditionallyOnBootstrap(
		configParams,
		netlinkshim.NewRealNetlink,
		v3Client,
	)
}
