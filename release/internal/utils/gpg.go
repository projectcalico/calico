// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

// GetGPGPubKey takes a GPG key ID and fetches the ascii-armored GPG public key
func GetGPGPubKey(gpgKeyID string) (string, error) {
	logrus.Debugf("Getting ascii-armored public key for GPG key %s", gpgKeyID)

	cmdArgs := []string{"--armor", "--export", gpgKeyID}
	logrus.Debugf("running gpg with args %s", strings.Join(cmdArgs, " "))
	gpgOut, err := command.Run("gpg", cmdArgs)
	if err != nil {
		return "", fmt.Errorf("exporting gpg key: %w", err)
	}
	return string(gpgOut), nil
}

// GPGTestSign signs a throwaway message with the given key, so that gpg-agent asks for
// the passphrase (and caches it) now, rather than part way through a long build.
func GPGTestSign(gpgKeyID string) error {
	cmd := exec.Command("gpg", "--local-user", gpgKeyID, "--sign", "--output", os.DevNull)
	cmd.Stdin = strings.NewReader("release tool GPG check\n")
	// Leave stdout/stderr on the terminal so a curses or tty pinentry can prompt.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("test signing with GPG key %s: %w", gpgKeyID, err)
	}
	return nil
}

// GPGAgentCacheTTLs returns gpg-agent's effective default-cache-ttl (how long a passphrase
// stays cached after its last use) and max-cache-ttl (how long it can stay cached at all).
func GPGAgentCacheTTLs() (defaultTTL, maxTTL time.Duration, err error) {
	out, err := command.Run("gpgconf", []string{"--list-options", "gpg-agent"})
	if err != nil {
		return 0, 0, fmt.Errorf("listing gpg-agent options: %w", err)
	}
	ttls := map[string]time.Duration{}
	for _, line := range strings.Split(out, "\n") {
		// Fields are name:flags:level:description:type:alt-type:argname:default:argdef:value,
		// and value is empty when the option is left at its default.
		f := strings.Split(line, ":")
		if len(f) < 10 || (f[0] != "default-cache-ttl" && f[0] != "max-cache-ttl") {
			continue
		}
		v := f[9]
		if v == "" {
			v = f[7]
		}
		secs, err := strconv.Atoi(v)
		if err != nil {
			return 0, 0, fmt.Errorf("parsing gpg-agent %s %q: %w", f[0], v, err)
		}
		ttls[f[0]] = time.Duration(secs) * time.Second
	}
	return ttls["default-cache-ttl"], ttls["max-cache-ttl"], nil
}
