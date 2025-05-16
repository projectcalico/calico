// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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
	"io"
	"os"
	"path/filepath"

	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"

	"github.com/projectcalico/calico/lib/std/log"
)

func connect(cfg *Config) (*ssh.Session, error) {
	key, err := os.ReadFile(cfg.Key)
	if err != nil {
		log.WithField("key", cfg.Key).WithError(err).Error("Unable to read ssh key")
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	khFile := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
	if cfg.KnownHosts != "" {
		khFile = cfg.KnownHosts
	}
	kh, err := knownhosts.NewDB(khFile)
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User: cfg.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: kh.HostKeyCallback(),
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
	return runSSHCommandWithStdin(cfg, command, nil)
}

func runSSHCommandWithStdin(cfg *Config, command string, stdin io.Reader) (string, error) {
	session, err := connect(cfg)
	if err != nil {
		log.WithError(err).Error("failed to connect to remote host")
		return "", err
	}
	defer session.Close()
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	if stdin != nil {
		session.Stdin = stdin
	}
	log.WithField("command", command).Debug("Running command in remote host")
	if err := session.Run(command); err != nil {
		log.WithError(err).Error("Failed to run command")
		return "", err
	}
	return stdoutBuf.String(), nil
}
