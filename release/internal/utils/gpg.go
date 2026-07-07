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
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

// GetGPGPubKey takes a GPG key ID and fetches the ascii-armored GPG public key
func GetGPGPubKey(gpgKeyID string) (string, error) {
	logrus.Debugf("Getting ascii-armored public key for GPG key %s", gpgKeyID)

	cmdArgs := []string{"--armor", "--export", gpgKeyID}
	logrus.Debugf("Running gpg with args %s", strings.Join(cmdArgs, " "))
	gpgOut, err := command.Run("gpg", cmdArgs)
	if err != nil {
		return "", fmt.Errorf("exporting gpg key: %w", err)
	}
	return string(gpgOut), nil
}

// SignRPMFiles takes a GPG key ID, which must have already been
// imported into the RPM database, and uses it to sign a list of
// RPM files. We use --rpmv4 here to ensure that, even on newer
// RPM versions, we're using backwards-compatible RPM signatures.
func SignRPMFiles(gpgKeyID string, rpmFiles []string) error {
	logrus.Infof("Signing RPM files with GPG key %s", gpgKeyID)
	cmdArgs := []string{
		"-D", fmt.Sprintf("%%_openpgp_sign_id %s", gpgKeyID),
		"--resign",
		"--rpmv4",
	}
	cmdArgs = append(cmdArgs, rpmFiles...)
	logrus.Debugf("Running rpmsign with args %s", strings.Join(cmdArgs, " "))
	_, err := command.Run("rpmsign", cmdArgs)
	if err != nil {
		return fmt.Errorf("unable to sign RPM files: %w", err)
	}
	return nil
}

// CheckRPMSig takes an RPM filename/path and runs rpmkeys --checksig
// on it to ensure that the signature and package digest are correct
func CheckRPMSig(rpmFile string) error {
	logrus.Debugf("Checking file %s for RPM signature", rpmFile)
	cmdArgs := []string{
		"--checksig",
		rpmFile,
	}
	rpmOut, err := command.Run("rpmkeys", cmdArgs)
	if err != nil {
		return fmt.Errorf("unable to check RPM signature: %w", err)
	}
	rpmOutFields := strings.Fields(rpmOut)
	if len(rpmOutFields) == 0 {
		return fmt.Errorf("rpmkeys --checksig returned no output")
	}
	if strings.Contains(rpmOut, "NOT OK") {
		logrus.Errorf("RPM signature/digest check failed: %s", rpmOut)
		return fmt.Errorf("RPM signature/digest check failed: %s", rpmOut)
	}
	return nil
}

// CheckRPMSigs takes a list of RPM file names/paths and runs
func CheckRPMSigs(rpmFiles []string) error {
	logrus.Infof("Checking files for RPM signatures")
	var errs []error
	for _, rpmFile := range rpmFiles {
		if err := CheckRPMSig(rpmFile); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
