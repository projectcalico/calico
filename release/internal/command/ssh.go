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

package command

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/sirupsen/logrus"
	"github.com/skeema/knownhosts"
)

// SSHConfig holds the configuration for an SSH connection
type SSHConfig struct {
	Host    string
	User    string
	KeyPath string
	Port    string
}

// NewSSHConfig creates a new SSHConfig
func NewSSHConfig(host, user, keyPath, port string) *SSHConfig {
	return &SSHConfig{
		Host:    host,
		User:    user,
		KeyPath: keyPath,
		Port:    port,
	}
}

// Args returns the ssh command string arguments
func (s *SSHConfig) Args() string {
	str := []string{"-i", s.KeyPath, "-p", s.Port, "-q", "-o StrictHostKeyChecking=no", "-o UserKnownHostsFile=/dev/null"}
	return strings.Join(str, " ")
}

// HostString returns the host string in the format user@host
func (s *SSHConfig) HostString() string {
	return s.User + "@" + s.Host
}

// Address returns the address in the format host:port
func (s *SSHConfig) Address() string {
	return fmt.Sprintf("%s:%s", s.Host, s.Port)
}

func connect(sshConfig *SSHConfig) (*ssh.Session, error) {
	key, err := os.ReadFile(sshConfig.KeyPath)
	if err != nil {
		logrus.WithField("key", sshConfig.KeyPath).WithError(err).Error("Unable to read ssh key")
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User: sshConfig.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// This callback mimics the behavior of ssh -o StrictHostKeyChecking=no
		HostKeyCallback: ssh.HostKeyCallback(func(host string, remote net.Addr, pubKey ssh.PublicKey) error {
			knownHostsFilePath := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
			k, err := knownhosts.NewDB(knownHostsFilePath)
			if err != nil {
				return err
			}
			err = k.HostKeyCallback()(host, remote, pubKey)
			if knownhosts.IsHostKeyChanged(err) {
				return fmt.Errorf("host key changed: %v", err)
			} else if knownhosts.IsHostUnknown(err) {
				f, err := os.OpenFile(knownHostsFilePath, os.O_APPEND|os.O_WRONLY, 0o600)
				if err != nil {
					return err
				}
				defer f.Close()
				err = knownhosts.WriteKnownHost(f, host, remote, pubKey)
				if err != nil {
					return err
				}
				return nil
			}
			return err
		}),
	}
	client, err := ssh.Dial("tcp", sshConfig.Address(), config)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	return session, nil
}

// RunSSHCommand runs an a command on a remote host and returns the output
func RunSSHCommand(sshConfig *SSHConfig, command string) (string, error) {
	session, err := connect(sshConfig)
	if err != nil {
		logrus.WithError(err).Error("Failed to connect to remote host")
		return "", err
	}
	defer session.Close()
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	logrus.WithField("command", command).Info("Running command in remote host")
	if err := session.Run(command); err != nil {
		return "", err
	}
	return stdoutBuf.String(), nil
}
