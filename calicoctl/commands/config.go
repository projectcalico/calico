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

package commands

import (
	"errors"
	"os"
	"strings"

	"fmt"

	"github.com/docopt/docopt-go"
	"github.com/projectcalico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

func Config(args []string) {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl config set <NAME> <VALUE> [--node=<NODE>]
                                      [--raw=(bgp|felix)]
                                      [--config=<CONFIG>]
  calicoctl config unset <NAME> [--node=<NODE>]
                                [--raw=(bgp|felix)]
                                [--config=<CONFIG>]
  calicoctl config get <NAME> [--node=<NODE>]
                              [--raw=(bgp|felix)]
                              [--config=<CONFIG>]

Examples:
  # Turn off the full BGP node-to-node mesh
  calicoctl config set nodeToNodeMesh off

  # Set global log level to warning
  calicoctl config set logLevel warning

  # Set log level to info for node "node1"
  calicoctl config set logLevel info --node=node1

  # Display the current setting for the nodeToNodeMesh
  calicoctl config get nodeToNodeMesh

Options:
  -n --node=<NODE>      The node name.
     --raw=(bgp|felix)  Apply raw configuration for the specified component.
                        This option should be used with care; the data is not
                        validated and it is possible to configure or remove
                        data that may prevent the component from working as
                        expected.
  -c --config=<CONFIG>  Path to the file containing connection configuration in
                        YAML or JSON format.
                        [default: /etc/calico/calicoctl.cfg]

Description:

These commands can be used to manage global system-wide configuration and some
node-specific low level configuration.

The --node option is used to specify the node name for low-level configuration
that is specific to a particular node.

For configuration that has both global values and node-specific values, the
--node parameter is optional:  including the parameter will manage the
node-specific value,  excluding it will manage the global value.  For these
options, if the node-specific value is unset, the global value will be used on
the node.

For configuration that is only global, the --node option should not be
included.  Unsetting the global value will return it to it's original default.

For configuration that is node-specific only, the --node option should be
included.  Unsetting the node value will remove the configuration, and for
supported configuration will then inherit the value from the global settings.

The table below details the valid config options.

 Name            | Scope       | Value                                  |
-----------------+-------------+----------------------------------------+
 logLevel        | global,node | none,debug,info,warning,error,critical |
 nodeToNodeMesh  | global      | on,off                                 |
 asNumber        | global      | 0-4294967295                           |
 ipip            | global      | on,off                                 |
`
	parsedArgs, err := docopt.Parse(doc, args, true, "calicoctl", false, false)
	if err != nil {
		fmt.Printf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.\n", strings.Join(args, " "))
		os.Exit(1)
	}
	if len(parsedArgs) == 0 {
		return
	}

	// Load the client config and connect.
	cf := parsedArgs["--config"].(string)
	client, err := clientmgr.NewClient(cf)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// From the command line arguments construct the Config object to send to the client.
	node := argutils.ArgStringOrBlank(parsedArgs, "--node")
	raw := argutils.ArgStringOrBlank(parsedArgs, "--raw")
	name := argutils.ArgStringOrBlank(parsedArgs, "<NAME>")
	value := argutils.ArgStringOrBlank(parsedArgs, "<VALUE>")

	// For now we map each option through to separate config methods, but
	// eventually we'll aim to have a config style resource and this will
	// become more generic.
	var ct configType
	switch raw {
	case "felix":
		ct = rawFelixConfig{name: name, c: client.Config()}
	case "bgp":
		ct = rawBGPConfig{name: name, c: client.Config()}
	case "":
		switch strings.ToLower(name) {
		case "loglevel":
			ct = loglevel{client.Config()}
		case "nodetonodemesh":
			ct = nodemesh{client.Config()}
		case "asnumber":
			ct = asnum{client.Config()}
		case "ipip":
			ct = ipip{client.Config()}
		default:
			fmt.Printf("Error executing command: unrecognised config name '%s'\n", name)
			os.Exit(1)
		}

	default:
		fmt.Printf("Error executing command: unrecognised component '%s'\n", raw)
		os.Exit(1)
	}

	if parsedArgs["set"].(bool) {
		err = ct.set(value, node)
	} else if parsedArgs["unset"].(bool) {
		err = ct.unset(node)
	} else {
		err = ct.get(node)
	}

	if err != nil {
		fmt.Printf("Error executing command: %s\n", err)
		os.Exit(1)
	}

	return
}

// Config management interface.
type configType interface {
	set(value, node string) error
	unset(node string) error
	get(node string) error
}

// loglevel implements the configType interface.
type loglevel struct {
	c client.ConfigInterface
}

func (l loglevel) set(value, node string) error {
	if node == "" {
		return l.c.SetGlobalLogLevel(value)
	} else {
		return l.c.SetNodeLogLevel(node, value)
	}
}

func (l loglevel) unset(node string) error {
	if node == "" {
		return l.c.SetGlobalLogLevel(client.GlobalDefaultLogLevel)
	} else {
		return l.c.SetNodeLogLevelUseGlobal(node)
	}
}

func (l loglevel) get(node string) error {
	var level string
	var location client.ConfigLocation
	var err error
	if node == "" {
		level, err = l.c.GetGlobalLogLevel()
		location = client.ConfigLocationNone
	} else {
		level, location, err = l.c.GetNodeLogLevel(node)
	}
	if err != nil {
		return err
	}
	if location == client.ConfigLocationGlobal {
		fmt.Printf("%s (inherited from global)\n", level)
	} else {
		fmt.Printf("%s\n", level)
	}
	return nil
}

// nodemesh implements the configType interface.
type nodemesh struct {
	c client.ConfigInterface
}

func (n nodemesh) set(value, node string) error {
	if node != "" {
		return errors.New("--node should not be specified")
	}

	switch value {
	case "on":
		return n.c.SetNodeToNodeMesh(true)
	case "off":
		return n.c.SetNodeToNodeMesh(false)
	default:
		return errors.New("invalid value '" + value + "'")
	}
}

func (n nodemesh) unset(node string) error {
	if node != "" {
		return errors.New("--node should not be specified")
	}

	return n.c.SetNodeToNodeMesh(client.GlobalDefaultNodeToNodeMesh)
}

func (n nodemesh) get(node string) error {
	if node != "" {
		return errors.New("--node should not be specified")
	}

	enabled, err := n.c.GetNodeToNodeMesh()
	if err != nil {
		return err
	}
	if enabled {
		fmt.Println("on")
	} else {
		fmt.Println("off")
	}
	return nil
}

// ipip implements the configType interface.
type ipip struct {
	c client.ConfigInterface
}

func (i ipip) set(value, node string) error {
	if node != "" {
		return errors.New("--node should not be specified")
	}

	switch value {
	case "on":
		return i.c.SetGlobalIPIP(true)
	case "off":
		return i.c.SetGlobalIPIP(false)
	default:
		return errors.New("invalid value '" + value + "'")
	}
}

func (i ipip) unset(node string) error {
	if node != "" {
		return errors.New("--node should not be specified")
	}

	return i.c.SetGlobalIPIP(client.GlobalDefaultIPIP)
}

func (i ipip) get(node string) error {
	if node != "" {
		return errors.New("--node should not be specified")
	}

	enabled, err := i.c.GetGlobalIPIP()
	if err != nil {
		return err
	}
	if enabled {
		fmt.Println("on")
	} else {
		fmt.Println("off")
	}
	return nil
}

// asnum implements the configType interface.
type asnum struct {
	c client.ConfigInterface
}

func (a asnum) set(value, node string) error {
	if node != "" {
		return errors.New("--node should not be specified")
	}

	asn, err := numorstring.ASNumberFromString(value)
	if err != nil {
		return errors.New("the supplied AS number is not valid")
	}

	return a.c.SetGlobalASNumber(asn)
}

func (a asnum) unset(node string) error {
	if node != "" {
		return errors.New("--node should not be specified")
	}

	return a.c.SetGlobalASNumber(client.GlobalDefaultASNumber)
}

func (a asnum) get(node string) error {
	if node != "" {
		return errors.New("--node should not be specified")
	}

	asn, err := a.c.GetGlobalASNumber()
	if err != nil {
		return err
	}
	fmt.Println(asn.String())
	return nil
}

// rawFelixConfig implements the configType interface, and is used for setting
// raw Felix configuration.
type rawFelixConfig struct {
	name string
	c    client.ConfigInterface
}

func (r rawFelixConfig) set(value, node string) error {
	return r.c.SetFelixConfig(r.name, node, value)
}

func (r rawFelixConfig) unset(node string) error {
	return r.c.UnsetFelixConfig(r.name, node)
}

func (r rawFelixConfig) get(node string) error {
	value, set, err := r.c.GetFelixConfig(r.name, node)
	if err != nil {
		return err
	}
	if !set {
		fmt.Println("(unset)")
	} else {
		fmt.Println(value)
	}
	return nil
}

// rawBGPConfig implements the configType interface, and is used for setting
// raw BGP configuration.
type rawBGPConfig struct {
	name string
	c    client.ConfigInterface
}

func (r rawBGPConfig) set(value, node string) error {
	return r.c.SetBGPConfig(r.name, node, value)
}

func (r rawBGPConfig) unset(node string) error {
	return r.c.UnsetBGPConfig(r.name, node)
}

func (r rawBGPConfig) get(node string) error {
	value, set, err := r.c.GetBGPConfig(r.name, node)
	if err != nil {
		return err
	}
	if !set {
		fmt.Println("(unset)")
	} else {
		fmt.Println(value)
	}
	return nil
}
