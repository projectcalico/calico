// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package flannelmigration

import (
	"fmt"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/kelseyhightower/envconfig"

	"github.com/joho/godotenv"

	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

const (
	flannelEnvFile        = "/host/run/flannel/subnet.env"
	canalDaemonsetName    = "canal"
	calicoConfigMapName   = "calico-config"
	calicoConfigMapMtuKey = "veth_mtu"
)

//Flannel migration controller configurations
type Config struct {
	// FlannelNetwork should has same value as Flannel "network" config.
	// This is the IPv4 network in CIDR format used for the entire flannel network.
	// This config item is auto detected from /run/flannel/subnet.env.
	FlannelNetwork string `default:"" split_words:"true"`

	// Name of Flannel daemonset in kube-system namespace.
	// This could be a Canal daemonset where the controller will autodetect.
	// Default is kube-flannel-ds-amd64
	FlannelDaemonsetName string `default:"kube-flannel-ds-amd64" split_words:"true"`

	// FlannelMTU is the mtu used by flannel vxlan tunnel interface.
	// This config item is auto detected from /run/flannel/subnet.env.
	FlannelMTU int `default:"0" split_words:"true"`

	// This option indicates if IP masquerade is enabled for traffic destined for outside the flannel network.
	// This config item is auto detected from /run/flannel/subnet.env.
	FlannelIPMasq bool `default:"true" split_words:"true"`

	// The following config items is not mandatory.
	// The default value is set to be the same default value as Flannel.
	// If an item is set to a non-default value in existing Flannel network, same value has to be set here.

	// FlannelSubnetLen should has same value as Flannel "SubnetLen" configuration option.
	// It is the size of the subnet allocated to each host. Default value is 24.
	FlannelSubnetLen int `default:"24" split_words:"true"`

	// FlannelAnnotationPrefix should has same value as Flannel "kube-annotation-prefix" commandline option.
	FlannelAnnotationPrefix string `default:"flannel.alpha.coreos.com" split_words:"true"`

	// FlannelVNI is the VNI id used by Flannel vxlan network.
	FlannelVNI int `default:"1" split_words:"true"`

	// FlannelPort is the port number used by Flannel vxlan network.
	FlannelPort int `default:"8472" split_words:"true"`

	// Name of Calico daemonset in kube-system namespace. Default is "calico-node".
	CalicoDaemonsetName string `default:"calico-node" split_words:"true"`

	// CNI config directory. The full path of the directory in which to search for CNI config files. Default: /etc/cni/net.d
	CNIConfigDir string `default:"/etc/cni/net.d" split_words:"true"`

	// Node name which migration controller is running. This ENV is passed via Kubernetes downwards API.
	PodNodeName string `default:"" split_words:"true"`
}

// Parse parses envconfig and stores in Config struct.
func (c *Config) Parse() error {
	err := envconfig.Process("", c)
	if err != nil {
		return err
	}

	// Work out config items based on env file.
	_, err = os.Stat(flannelEnvFile)
	if err != nil {
		return err
	}

	if c.FlannelNetwork, err = readFlannelEnvFile("FLANNEL_NETWORK"); err != nil {
		return err
	}

	var masq string
	if masq, err = readFlannelEnvFile("FLANNEL_IPMASQ"); err != nil {
		return err
	}
	if c.FlannelIPMasq, err = strconv.ParseBool(masq); err != nil {
		return err
	}

	var mtu string
	if mtu, err = readFlannelEnvFile("FLANNEL_MTU"); err != nil {
		return err
	}
	if c.FlannelMTU, err = strconv.Atoi(mtu); err != nil {
		return err
	}

	return c.ValidateConfig()
}

func (c *Config) IsRunningCanal() bool {
	return c.FlannelDaemonsetName == canalDaemonsetName
}

// Validate Flannel migration controller configurations.
func (c *Config) ValidateConfig() error {
	// Check cluster pod CIDR
	if c.FlannelNetwork == "" {
		return fmt.Errorf("Missing FlannelNetwork config")
	}
	_, _, err := cnet.ParseCIDR(c.FlannelNetwork)
	if err != nil {
		return fmt.Errorf("Failed to parse cluster pod CIDR '%s'", c.FlannelNetwork)
	}

	// Check Flannel daemonset name.
	if c.FlannelDaemonsetName == "" {
		return fmt.Errorf("Missing FlannelDaemonsetName config")
	}

	// Check Flannel MTU.
	if c.FlannelMTU == 0 {
		return fmt.Errorf("Missing FlannelMTU config")
	}

	// Check pod node name
	if c.PodNodeName == "" {
		return fmt.Errorf("Missing PodNodeName config")
	}

	return nil
}

func readFlannelEnvFile(key string) (string, error) {
	items, err := godotenv.Read(flannelEnvFile)
	if err != nil {
		log.Errorf("Failed to read Flannel env file.")
		return "", err
	}

	if val, ok := items[key]; ok {
		return val, nil
	}

	return "", fmt.Errorf("key %s not found in Flannel env file", key)
}
