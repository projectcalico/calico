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

package driver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	csi "github.com/container-storage-interface/spec/lib/go/csi"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const (
	VER            string = "0.1"
	CONFIG_FILE    string = "/etc/calico/csi/nodeagent.json"
	NODEAGENT_HOME string = "/var/run/nodeagent"
	MOUNT_DIR      string = "/mount"
	CREDS_DIR      string = "/creds"
	LOG_LEVEL_WARN string = "WARNING"
	CSI_SOCK       string = "/csi/csi.sock"
)

// ConfigurationOptions may be used to setup the driver.
// These are optional and most users will not depened on them and will instead use the defaults.
type ConfigurationOptions struct {
	// Location on the node's filesystem where the driver will host the
	// per workload directory and the credentials for the workload.
	// Default: /var/run/nodeagent
	NodeAgentManagementHomeDir string `json:"nodeagent_management_home,omitempty"`
	// Relative location to NodeAgentManagementHomeDir where per workload directory
	// will be created.
	// Default: /mount
	// For example: /mount here implies /var/run/nodeagent/mount/ directory
	// on the node.
	NodeAgentWorkloadHomeDir string `json:"nodeagent_workload_home,omitempty"`
	// Relative location to NodeAgentManagementHomeDir where per workload credential
	// files will be created.
	// Default: /creds
	// For example: /creds here implies /var/run/nodeagent/creds/ directory
	NodeAgentCredentialsHomeDir string `json:"nodeagent_credentials_home,omitempty"`
	// Log level for loggint to node syslog. Options: INFO|WARNING
	// Default: WARNING
	LogLevel string `json:"log_level,omitempty"`
	// Node ID used for node service calls.
	// Default: ""
	NodeID string `json:"node_id,omitempty"`
	// Location of the unix domain socket that the Kubelet communicates with the CSI plugin over.
	// Default: /csi/csi.sock
	Endpoint string `json:"endpoint,omitempty"`
}

type Driver struct {
	nodeService

	server  *grpc.Server
	options *ConfigurationOptions
}

func NewDriver(config *ConfigurationOptions) *Driver {
	return &Driver{
		options:     config,
		server:      grpc.NewServer(),
		nodeService: newNodeService(config),
	}
}

func (d *Driver) Run() error {
	// register the node server since that should be all that we need.
	csi.RegisterIdentityServer(d.server, d)
	csi.RegisterNodeServer(d.server, d)

	// Remove any leftover socket from a previous run
	if err := os.Remove(d.options.Endpoint); err != nil && !os.IsNotExist(err) {
		log.Errorf("Could not remove unix domain socket %s: %v", d.options.Endpoint, err)
		return err
	}

	// Create an http listener here to provide to the grpc server to serve.
	listener, err := net.Listen("unix", d.options.Endpoint)
	if err != nil {
		log.Errorf("Server could not listen at %s: %v", d.options.Endpoint, err)
		return err
	}

	log.Infof("Server listening at %v", listener.Addr())
	return d.server.Serve(listener)
}

func RetrieveConfig() (*ConfigurationOptions, error) {
	config := ConfigurationOptions{}
	if _, err := os.Stat(CONFIG_FILE); err == nil {
		// Read the config from the file.
		bytes, err := ioutil.ReadFile(CONFIG_FILE)
		if err != nil {
			return nil, fmt.Errorf("Unable to read configuration at %s: %v", CONFIG_FILE, err)
		}

		err = json.Unmarshal(bytes, &config)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse configuration at %s: %v", CONFIG_FILE, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	// Add the default values to the configuration if required.
	if len(config.NodeAgentManagementHomeDir) == 0 {
		config.NodeAgentManagementHomeDir = NODEAGENT_HOME
	}

	if len(config.NodeAgentWorkloadHomeDir) == 0 {
		config.NodeAgentWorkloadHomeDir = MOUNT_DIR
	}

	if len(config.NodeAgentCredentialsHomeDir) == 0 {
		config.NodeAgentCredentialsHomeDir = CREDS_DIR
	}

	if len(config.LogLevel) == 0 {
		config.LogLevel = LOG_LEVEL_WARN
	}

	if len(config.Endpoint) == 0 {
		config.Endpoint = CSI_SOCK
	}

	// Convert to absolute paths.
	var prefix string = ""
	if !strings.HasPrefix(config.NodeAgentWorkloadHomeDir, "/") {
		prefix = "/"
	}
	config.NodeAgentWorkloadHomeDir = strings.Join([]string{config.NodeAgentManagementHomeDir, config.NodeAgentWorkloadHomeDir}, prefix)

	prefix = ""
	if !strings.HasPrefix(config.NodeAgentCredentialsHomeDir, "/") {
		prefix = "/"
	}
	config.NodeAgentCredentialsHomeDir = strings.Join([]string{config.NodeAgentManagementHomeDir, config.NodeAgentCredentialsHomeDir}, prefix)

	return &config, nil
}
