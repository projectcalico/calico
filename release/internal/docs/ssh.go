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

package docs

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/sirupsen/logrus"
)

//go:embed data/key.pub
var publicKey string

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
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			keyStr := key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())
			publicKey = strings.TrimSuffix(publicKey, "\n")
			if keyStr != publicKey {
				return fmt.Errorf("unknown host key")
			}
			return nil
		},
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
