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
	"bytes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/sirupsen/logrus"
	"github.com/skeema/knownhosts"
)

func connect(cfg *Config) (*ssh.Session, error) {
	key, err := os.ReadFile(cfg.Key)
	if err != nil {
		logrus.WithField("key", cfg.Key).WithError(err).Error("Unable to read ssh key")
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User: cfg.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(host string, remote net.Addr, key ssh.PublicKey) error {
			knownHostsFilePath := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
			k, err := knownhosts.NewDB(knownHostsFilePath)
			if err != nil {
				return err
			}
			err = k.HostKeyCallback()(host, remote, key)
			if knownhosts.IsHostKeyChanged(err) {
				return fmt.Errorf("host key changed: %v", err)
			} else if knownhosts.IsHostUnknown(err) {
				// When HostKeyCallback returns an error with IsHostUnknown,
				// and HostKey is set, we check the host key against the HostKey file.
				// If the host key matches, attempt to add the host key to the known_hosts file
				// as the rsync command requires the host key to be in the known_hosts file.
				if cfg.HostKey != "" {
					keyStr := key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())
					pubKey, err := os.ReadFile(cfg.HostKey)
					if err != nil {
						return err
					}
					publicKey := strings.TrimSuffix(string(pubKey), "\n")

					if publicKey == keyStr {
						f, err := os.OpenFile(knownHostsFilePath, os.O_APPEND|os.O_WRONLY, 0o600)
						if err != nil {
							// If we can't open the known_hosts file to add the host key,
							// simply log the error and continue since the host key is valid.
							logrus.WithError(err).Error("Failed to open known_hosts file to add host key")
							return nil
						}
						defer f.Close()
						err = knownhosts.WriteKnownHost(f, host, remote, key)
						if err != nil {
							// If we can't write the host key to the known_hosts file,
							// simply log the error and continue since the host key is valid.
							logrus.WithError(err).Error("Failed to write host key to known_hosts file")
							return nil
						}
						return nil
					}
				}
				return fmt.Errorf("unknown host, either add to known_hosts file or set HostKey in configuration: %v", err)
			}
			return err
		}),
	}
	client, err := ssh.Dial("tcp", cfg.Address(), config)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	return session, nil
}

func runSSHCommand(cfg *Config, command string) (string, error) {
	session, err := connect(cfg)
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
