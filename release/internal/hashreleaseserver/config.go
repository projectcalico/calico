// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package hashreleaseserver

import (
	"fmt"
	"strings"
)

// Config holds the configuration for an SSH connection
type Config struct {
	// Host is the host for the SSH connection
	Host string

	// User is the user for the SSH connection
	User string

	// Key is the path to the SSH key
	Key string

	// Port is the port for the SSH connection
	Port string

	// KnownHosts is the absolute path to the known_hosts file
	// to use for the user host key database instead of ~/.ssh/known_hosts
	KnownHosts string
}

// RSHCommand returns the ssh command for rsync to use for the connection
func (s *Config) RSHCommand() string {
	str := []string{"ssh", "-i", s.Key, "-p", s.Port, "-q", "-o StrictHostKeyChecking=yes"}
	if s.KnownHosts != "" {
		str = append(str, "-o UserKnownHostsFile="+s.KnownHosts)
	}
	return strings.Join(str, " ")
}

// HostString returns the host string in the format user@host
func (s *Config) HostString() string {
	return s.User + "@" + s.Host
}

// Address returns the address in the format host:port
func (s *Config) Address() string {
	return fmt.Sprintf("%s:%s", s.Host, s.Port)
}

func (s *Config) Valid() bool {
	return s.Host != "" && s.User != "" && s.Key != "" && s.Port != ""
}
