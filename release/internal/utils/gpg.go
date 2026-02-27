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
	"strings"

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
