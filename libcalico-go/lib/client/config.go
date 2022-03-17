// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

type ConfigLocation int8

const (
	ConfigLocationNone ConfigLocation = iota
	ConfigLocationNode
	ConfigLocationGlobal
)

var logToBgp = map[string]string{
	"none":     "none",
	"debug":    "debug",
	"info":     "info",
	"warning":  "none",
	"error":    "none",
	"critical": "none",
}

const (
	GlobalDefaultASNumber       = 64512
	GlobalDefaultLogLevel       = "info"
	GlobalDefaultIPIP           = false
	GlobalDefaultNodeToNodeMesh = true
)

// ConfigInterface provides methods for setting, unsetting and retrieving low
// level config options.
type ConfigInterface interface {
	SetNodeToNodeMesh(bool) error
	GetNodeToNodeMesh() (bool, error)
	SetGlobalASNumber(numorstring.ASNumber) error
	GetGlobalASNumber() (numorstring.ASNumber, error)
	SetGlobalIPIP(bool) error
	GetGlobalIPIP() (bool, error)
	SetNodeIPIPTunnelAddress(string, *net.IP) error
	GetNodeIPIPTunnelAddress(string) (*net.IP, error)
	SetGlobalLogLevel(string) error
	GetGlobalLogLevel() (string, error)
	SetNodeLogLevel(string, string) error
	SetNodeLogLevelUseGlobal(string) error
	GetNodeLogLevel(string) (string, ConfigLocation, error)
	GetFelixConfig(string, string) (string, bool, error)
	SetFelixConfig(string, string, string) error
	UnsetFelixConfig(string, string) error
	GetBGPConfig(string, string) (string, bool, error)
	SetBGPConfig(string, string, string) error
	UnsetBGPConfig(string, string) error
}

// config implements ConfigInterface
type config struct {
	c *Client
}

// newConfig returns a new ConfigInterface bound to the supplied client.
func newConfigs(c *Client) ConfigInterface {
	return &config{c}
}

// The configuration interface provides the ability to set and get low-level,
// or system-wide configuration options.

// SetNodeToNodeMesh sets the enabled state of the system-wide node-to-node mesh.
// When this is enabled, each calico/node instance automatically establishes a
// full BGP peering mesh between all nodes that support BGP.
func (c *config) SetNodeToNodeMesh(enabled bool) error {
	b, _ := json.Marshal(enabled)
	_, err := c.c.Backend.Apply(context.Background(), &model.KVPair{
		Key:   model.GlobalBGPConfigKey{Name: "NodeMeshEnabled"},
		Value: string(b),
	})
	return err
}

// GetNodeToNodeMesh returns the current enabled state of the system-wide
// node-to-node mesh option.  See SetNodeToNodeMesh for details.
func (c *config) GetNodeToNodeMesh() (bool, error) {
	var n bool
	if s, err := c.getValue(model.GlobalBGPConfigKey{Name: "NodeMeshEnabled"}); err != nil {
		log.Info("Error getting node mesh")
		return false, err
	} else if s == nil {
		log.Info("Return default node to node mesh")
		return GlobalDefaultNodeToNodeMesh, nil
	} else if err = json.Unmarshal([]byte(*s), &n); err != nil {
		log.WithField("NodeMeshEnabled", *s).Error("Error parsing node to node mesh")
		return false, err
	} else {
		log.Info("Returning configured node to node mesh")
		return n, nil
	}
}

// SetGlobalASNumber sets the global AS Number used by the BGP agent running
// on each node.  This may be overridden by an explicitly configured value in
// the node resource.
func (c *config) SetGlobalASNumber(asNumber numorstring.ASNumber) error {
	_, err := c.c.Backend.Apply(context.Background(), &model.KVPair{
		Key:   model.GlobalBGPConfigKey{Name: "AsNumber"},
		Value: asNumber.String(),
	})
	return err
}

// SetGlobalASNumber gets the global AS Number used by the BGP agent running
// on each node.  See SetGlobalASNumber for more details.
func (c *config) GetGlobalASNumber() (numorstring.ASNumber, error) {
	if s, err := c.getValue(model.GlobalBGPConfigKey{Name: "AsNumber"}); err != nil {
		return 0, err
	} else if s == nil {
		return GlobalDefaultASNumber, nil
	} else if asn, err := numorstring.ASNumberFromString(*s); err != nil {
		return 0, err
	} else {
		return asn, nil
	}
}

// SetGlobalIPIP sets the global IP in IP enabled setting inherited by all nodes
// in the Calico cluster.  When IP in IP is enabled, packets routed to IP addresses
// that fall within an IP in IP enabled Calico IP Pool, will be routed over an
// IP in IP tunnel.
func (c *config) SetGlobalIPIP(enabled bool) error {
	_, err := c.c.Backend.Apply(context.Background(), &model.KVPair{
		Key:   model.GlobalConfigKey{Name: "IpInIpEnabled"},
		Value: strconv.FormatBool(enabled),
	})
	return err
}

// GetGlobalIPIP gets the global IPIP enabled setting.  See SetGlobalIPIP for details.
func (c *config) GetGlobalIPIP() (bool, error) {
	if s, err := c.getValue(model.GlobalConfigKey{Name: "IpInIpEnabled"}); err != nil {
		return false, err
	} else if s == nil {
		return GlobalDefaultIPIP, nil
	} else if enabled, err := strconv.ParseBool(*s); err != nil {
		return false, err
	} else {
		return enabled, nil
	}
}

// SetNodeIPIPTunnelAddress sets the IP in IP tunnel address for a specific node.
// Felix will use this to configure the tunnel.
func (c *config) SetNodeIPIPTunnelAddress(node string, ip *net.IP) error {
	key := model.HostConfigKey{Hostname: node, Name: "IpInIpTunnelAddr"}
	if ip == nil {
		err := c.deleteConfig(key)
		return err
	} else {
		_, err := c.c.Backend.Apply(context.Background(), &model.KVPair{
			Key:   key,
			Value: ip.String(),
		})
		return err
	}
}

// GetNodeIPIPTunnelAddress gets the IP in IP tunnel address for a specific node.
// See SetNodeIPIPTunnelAddress for more details.
func (c *config) GetNodeIPIPTunnelAddress(node string) (*net.IP, error) {
	ip := &net.IP{}
	if s, err := c.getValue(model.HostConfigKey{Hostname: node, Name: "IpInIpTunnelAddr"}); err != nil {
		return nil, err
	} else if s == nil {
		return nil, nil
	} else if err = ip.UnmarshalText([]byte(*s)); err != nil {
		return nil, err
	} else {
		return ip, nil
	}
}

// SetGlobalLogLevel sets the system global log level used by the node.  This
// may be overridden on a per-node basis.
func (c *config) SetGlobalLogLevel(level string) error {
	return c.setLogLevel(
		level,
		model.GlobalConfigKey{Name: "LogSeverityScreen"},
		model.GlobalBGPConfigKey{Name: "loglevel"})
}

// GetGlobalLogLevel gets the current system global log level.
func (c *config) GetGlobalLogLevel() (string, error) {
	s, err := c.getValue(model.GlobalConfigKey{Name: "LogSeverityScreen"})
	if err != nil {
		return "", err
	} else if s == nil {
		return GlobalDefaultLogLevel, nil
	} else {
		return *s, nil
	}
}

// SetNodeLogLevel sets the node specific log level.  This overrides the global
// log level.
func (c *config) SetNodeLogLevel(node string, level string) error {
	return c.setLogLevel(level,
		model.HostConfigKey{Hostname: node, Name: "LogSeverityScreen"},
		model.NodeBGPConfigKey{Nodename: node, Name: "loglevel"})
}

// SetNodeLogLevelUseGlobal sets the node to use the global log level.
func (c *config) SetNodeLogLevelUseGlobal(node string) error {
	kf := model.HostConfigKey{Hostname: node, Name: "LogSeverityScreen"}
	kb := model.NodeBGPConfigKey{Nodename: node, Name: "loglevel"}
	err1 := c.deleteConfig(kf)
	err2 := c.deleteConfig(kb)

	// Return error or nil.
	if err1 != nil {
		return err1
	}
	return err2
}

// GetNodeLogLevel returns the current effective log level for the node.  The
// second return parameter indicates whether the value is explicitly set on the
// node or inherited from the system-wide global value.
func (c *config) GetNodeLogLevel(node string) (string, ConfigLocation, error) {
	s, err := c.getValue(model.HostConfigKey{Hostname: node, Name: "LogSeverityScreen"})
	if err != nil {
		return "", ConfigLocationNone, err
	} else if s == nil {
		l, err := c.GetGlobalLogLevel()
		return l, ConfigLocationGlobal, err
	} else {
		return *s, ConfigLocationNode, nil
	}
}

// GetFelixConfig provides a mechanism for getting arbitrary Felix configuration
// in the datastore.  A blank value for the node will get the global
// configuration.  If the boolean value returned is false, the configurations
// is unset and the return value should be ignored.
func (c *config) GetFelixConfig(name, node string) (string, bool, error) {
	value, err := c.getValue(getFelixConfigKey(name, node))
	if err != nil {
		return "", false, err
	} else if value == nil {
		return "", false, nil
	} else {
		return *value, true, nil
	}
}

// SetFelixConfig provides a mechanism for setting arbitrary Felix configuration
// in the datastore.  A blank value for the node will set the global
// configuration.
//
// Caution should be observed using this method as no validation is performed
// and changing arbitrary configuration may have unexpected consequences.
func (c *config) SetFelixConfig(name, node string, value string) error {
	_, err := c.c.Backend.Apply(context.Background(), &model.KVPair{
		Key:   getFelixConfigKey(name, node),
		Value: value,
	})
	return err
}

// UnsetFelixConfig provides a mechanism for unsetting arbitrary Felix
// configuration in the datastore.  A blank value for the node will unset the
// global felix configuration.
//
// Caution should be observed using this method as no validation is performed
// and changing arbitrary configuration may have unexpected consequences.
func (c *config) UnsetFelixConfig(name, node string) error {
	return c.deleteConfig(getFelixConfigKey(name, node))
}

// GetBGPConfig provides a mechanism for getting arbitrary BGP configuration
// in the datastore.  A blank value for the node will get the global
// configuration.  If the boolean value returned is false, the configurations
// is unset and the return value should be ignored.
func (c *config) GetBGPConfig(name, node string) (string, bool, error) {
	value, err := c.getValue(getBGPConfigKey(name, node))
	if err != nil {
		return "", false, err
	} else if value == nil {
		return "", false, nil
	} else {
		return *value, true, nil
	}
}

// SetBGPConfig provides a mechanism for setting arbitrary BGP configuration
// in the datastore.  A blank value for the node will set the global
// configuration.
//
// Caution should be observed using this method as no validation is performed
// and changing arbitrary configuration may have unexpected consequences.
func (c *config) SetBGPConfig(name, node string, value string) error {
	_, err := c.c.Backend.Apply(context.Background(), &model.KVPair{
		Key:   getBGPConfigKey(name, node),
		Value: value,
	})
	return err
}

// UnsetBGPConfig provides a mechanism for unsetting arbitrary BGP
// configuration in the datastore.  A blank value for the node will unset the
// global felix configuration.
//
// Caution should be observed using this method as no validation is performed
// and changing arbitrary configuration may have unexpected consequences.
func (c *config) UnsetBGPConfig(name, node string) error {
	return c.deleteConfig(getBGPConfigKey(name, node))
}

// getFelixConfigKey returns the model.Key interface for the Felix config.
func getFelixConfigKey(name, node string) model.Key {
	if node == "" {
		return model.GlobalConfigKey{Name: name}
	}
	return model.HostConfigKey{Hostname: node, Name: name}
}

// getBGPConfigKey returns the model.Key interface for the BGP config.
func getBGPConfigKey(name, node string) model.Key {
	if node == "" {
		return model.GlobalBGPConfigKey{Name: name}
	}
	return model.NodeBGPConfigKey{Nodename: node, Name: name}
}

// setLogLevel sets the log level fields with the appropriate log string value.
func (c *config) setLogLevel(level string, felixKey, bgpKey model.Key) error {
	bgpLevel, ok := logToBgp[level]
	if !ok {
		return erroredField("loglevel", level)
	}
	_, err1 := c.c.Backend.Apply(context.Background(), &model.KVPair{
		Key:   felixKey,
		Value: level,
	})
	_, err2 := c.c.Backend.Apply(context.Background(), &model.KVPair{
		Key:   bgpKey,
		Value: bgpLevel,
	})

	// Return error or nil.
	if err1 != nil {
		return err1
	}
	return err2
}

// deleteConfig deletes a resource and ignores deleted errors.
func (c *config) deleteConfig(key model.Key) error {
	_, err := c.c.Backend.Delete(context.Background(), key, "")
	if err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			return err
		}
	}
	return nil
}

// getValue returns the string value (pointer) or nil if the key does not
// exist in the datastore.
func (c *config) getValue(key model.Key) (*string, error) {
	kv, err := c.c.Backend.Get(context.Background(), key, "")
	if err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
			return nil, nil
		} else {
			return nil, err
		}
	} else {
		value := kv.Value.(string)
		return &value, nil
	}
}

// erroredField creates an ErrorValidation.
func erroredField(name string, value interface{}) error {
	err := errors.ErrorValidation{
		ErroredFields: []errors.ErroredField{
			errors.ErroredField{
				Name:  name,
				Value: fmt.Sprint(value),
			},
		},
	}
	return err
}
