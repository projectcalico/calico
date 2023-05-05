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
	"strconv"
	"strings"

	"github.com/kelseyhightower/envconfig"

	"github.com/joho/godotenv"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	FlannelEnvFile = "/host/run/flannel/subnet.env"
)

// Flannel migration controller configurations
type Config struct {
	// FlannelNetwork should has same value as Flannel "network" config.
	// This is the IPv4 network in CIDR format used for the entire flannel network.
	// This config item is auto detected from /run/flannel/subnet.env.
	FlannelNetwork string `default:"" split_words:"true"`

	// FlannelIpv6Network should has same value as Flannel "IPv6Network" config.
	// This is the IPv6 network in CIDR format used for the entire flannel network.
	// This config item is auto detected from /run/flannel/subnet.env.
	FlannelIpv6Network string `default:"" split_words:"true"`

	// Name of Flannel daemonset in kube-system namespace.
	// This could be a Canal daemonset where the controller will autodetect.
	// Default is kube-flannel-ds
	FlannelDaemonsetName string `default:"kube-flannel-ds" split_words:"true"`

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

	// FlannelIpv6SubnetLen should has same value as Flannel "IPv6SubnetLen" configuration option.
	// It is the size of the subnet allocated to each host. Default value is 64.
	FlannelIpv6SubnetLen int `default:"64" split_words:"true"`

	// FlannelAnnotationPrefix should has same value as Flannel "kube-annotation-prefix" commandline option.
	FlannelAnnotationPrefix string `default:"flannel.alpha.coreos.com" split_words:"true"`

	// FlannelVNI is the VNI id used by Flannel vxlan network.
	FlannelVNI int `default:"1" split_words:"true"`

	// FlannelPort is the port number used by Flannel vxlan network.
	FlannelPort int `default:"8472" split_words:"true"`

	// Name of Calico daemonset in kube-system namespace. Default is "calico-node".
	CalicoDaemonsetName string `default:"calico-node" split_words:"true"`

	// CNI config directory. The full path of the directory in which to search for CNI config files. Default: /etc/cni/net.d
	CniConfigDir string `default:"/etc/cni/net.d" split_words:"true"`

	// Node name which migration controller is running. This ENV is passed via Kubernetes downwards API.
	PodNodeName string `default:"" split_words:"true"`

	// FlannelSubnetEnv holds flannel-subnet-env value from migration ConfigMap.
	// This ENV is passed via ConfigMap.
	FlannelSubnetEnv string `default:"" split_words:"true"`

	// Total seconds to wait before migration controller exits.
	// This is used for debug/test purpose.
	DebugWaitBeforeExit int `default:"0" split_words:"true"`

	// Total seconds to wait before migration controller main thread starts.
	// This is used for debug/test purpose.
	DebugWaitBeforeStart int `default:"0" split_words:"true"`

	// Calico IPv4 ippool blockSize default value.
	DefaultIppoolSize int `default:"26" split_words:"true"`

	// Calico IPv6 ippool blockSize default value.
	DefaultIppoolSizeV6 int `default:"122" split_words:"true"`
}

// Parse parses envconfig and stores in Config struct.
func (c *Config) Parse() error {
	err := envconfig.Process("", c)
	if err != nil {
		return err
	}

	// Check pod node name is set.
	if c.PodNodeName == "" {
		return fmt.Errorf("Missing PodNodeName config")
	}

	// Check if FlannelSubnetEnv has been populated via ConfigMap.
	if !c.subnetEnvPopulated() {
		// Do nothing. This means migration controller is running the very first time.
		// Some of the config items will be auto detected by migration controller main thread.
		return nil
	}

	// Restore from json string to subnet.env file content.
	data := strings.Replace(c.FlannelSubnetEnv, ";", "\n", -1)
	if err = c.ReadFlannelConfig(data); err != nil {
		return err
	}
	if err = c.ValidateFlannelConfig(); err != nil {
		return err
	}

	return nil
}

func (c *Config) IsRunningCanal() bool {
	return c.FlannelDaemonsetName == canalDaemonsetName
}

func (c *Config) subnetEnvPopulated() bool {
	return c.FlannelSubnetEnv != ""
}

// Validate Flannel migration controller configurations.
func (c *Config) ValidateFlannelConfig() error {
	// Check cluster pod CIDR
	if c.FlannelNetwork == "" {
		return fmt.Errorf("Missing FlannelNetwork config")
	}
	_, _, err := cnet.ParseCIDR(c.FlannelNetwork)
	if err != nil {
		return fmt.Errorf("Failed to parse cluster pod CIDR '%s'", c.FlannelNetwork)
	}

	if c.FlannelIpv6Network != "" {
		_, _, err := cnet.ParseCIDR(c.FlannelIpv6Network)
		if err != nil {
			return fmt.Errorf("Failed to parse cluster pod CIDR '%s'", c.FlannelIpv6Network)
		}
	}

	// Check Flannel daemonset name.
	if c.FlannelDaemonsetName == "" {
		return fmt.Errorf("Missing FlannelDaemonsetName config")
	}

	// Check Flannel MTU.
	if c.FlannelMTU == 0 {
		return fmt.Errorf("Missing FlannelMTU config")
	}

	return nil
}

// Read Flannel config from content of /run/flannel/subnet.env.
func (c *Config) ReadFlannelConfig(data string) error {
	reader := strings.NewReader(data)
	config, err := godotenv.Parse(reader)
	if err != nil {
		return err
	}

	var ok bool
	if c.FlannelNetwork, ok = config["FLANNEL_NETWORK"]; !ok {
		return fmt.Errorf("Failed to get config item FLANNEL_NETWORK")
	}

	// IPv6 is optional, so don't fail if not present
	c.FlannelIpv6Network = config["FLANNEL_IPV6_NETWORK"]

	var masq string
	if masq, ok = config["FLANNEL_IPMASQ"]; !ok {
		return fmt.Errorf("Failed to get config item FLANNEL_IPMASQ")
	}
	if c.FlannelIPMasq, err = strconv.ParseBool(masq); err != nil {
		return err
	}

	var mtu string
	if mtu, ok = config["FLANNEL_MTU"]; !ok {
		return fmt.Errorf("Failed to get config item FLANNEL_MTU")
	}
	if c.FlannelMTU, err = strconv.Atoi(mtu); err != nil {
		return err
	}
	return nil
}
