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
	"os"
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
	if len(rpmFiles) == 0 {
		return fmt.Errorf("list of RPM files to sign is empty")
	}
	filteredRpmFiles, err := FilterRegularFiles(rpmFiles)
	if err != nil {
		logrus.Error("Sanitizing RPM files list failed")
		return fmt.Errorf("unable to sanitize RPM file list: %w", err)
	}
	if len(filteredRpmFiles) == 0 {
		// Every path was filtered out (e.g. all directories); invoking rpmsign
		// with no packages would only produce a confusing usage error.
		return fmt.Errorf("no regular RPM files to sign in the provided list")
	}
	logrus.Infof("Signing RPM files with GPG key %s", gpgKeyID)
	cmdArgs := []string{
		"-D", fmt.Sprintf("%%_openpgp_sign_id %s", gpgKeyID),
		"--resign",
		"--rpmv4",
	}
	cmdArgs = append(cmdArgs, filteredRpmFiles...)
	logrus.Debugf("Running rpmsign with args %s", strings.Join(cmdArgs, " "))
	if _, err := command.Run("rpmsign", cmdArgs); err != nil {
		return fmt.Errorf("unable to sign RPM files: %w", err)
	}
	return nil
}

// CheckRPMSig takes an RPM filename/path and runs rpmkeys --checksig
// on it to ensure that the signature and package digest are correct.
// Also run lstat on the file to ensure it exists before we shell out.
func CheckRPMSig(rpmFile string) error {
	logrus.Debugf("Checking file %s for RPM signature", rpmFile)
	cmdArgs := []string{
		"--checksig",
		rpmFile,
	}
	if _, err := os.Lstat(rpmFile); err != nil {
		return fmt.Errorf("could not validate rpm file exists: %w", err)
	}
	rpmOut, err := command.Run("rpmkeys", cmdArgs)
	if err != nil {
		return fmt.Errorf("unable to check RPM signature: %w", err)
	}
	if err := checkRPMSigOutput(rpmOut); err != nil {
		logrus.WithError(err).Error("RPM signature/digest check failed")
		return err
	}
	return nil
}

// checkRPMSigOutput inspects the output of `rpmkeys --checksig` and returns an
// error unless it confirms the signature and digests verified successfully.
// rpmkeys reports "NOT OK" when a check fails outright, and "NOKEY" when a
// signature could not be verified because the signing key is absent from the
// keyring. In the NOKEY case the signature was not actually verified, so — like
// an outright failure — it must be treated as an error rather than a pass.
//
// A passing line lists the checks that verified, e.g. "pkg.rpm: digests
// signatures OK". An *unsigned* package still passes its digest check and
// prints "pkg.rpm: digests OK" with a zero exit status — there is no signature
// to verify. Since the point of this check is to confirm packages are signed,
// the absence of a verified signature must also be treated as a failure.
//
// The result markers are matched as whitespace-separated tokens in the status
// portion of each line (everything after the "<filename>:" prefix) rather than
// as substrings of the whole line. This keeps a file name that happens to
// contain "signature", "NOKEY" or "NOT OK" from being mistaken for a check
// result — status tokens never contain a colon, so the last colon reliably
// separates the file name from the results.
func checkRPMSigOutput(rpmOut string) error {
	var sawStatus, sawSignature bool
	for _, line := range strings.Split(rpmOut, "\n") {
		status := line
		if i := strings.LastIndex(line, ":"); i >= 0 {
			status = line[i+1:]
		}
		tokens := strings.Fields(status)
		if len(tokens) == 0 {
			continue
		}
		sawStatus = true
		for i, tok := range tokens {
			switch strings.ToUpper(tok) {
			case "NOKEY":
				return fmt.Errorf("RPM signature/digest check failed: %s", rpmOut)
			case "OK":
				if i > 0 && strings.EqualFold(tokens[i-1], "NOT") {
					return fmt.Errorf("RPM signature/digest check failed: %s", rpmOut)
				}
			case "SIGNATURE", "SIGNATURES":
				sawSignature = true
			}
		}
	}
	if !sawStatus {
		return fmt.Errorf("rpmkeys --checksig returned no output")
	}
	// Having ruled out the failure markers above, a verified signature shows up
	// as a "signature"/"signatures" token in the OK line; its absence means the
	// package's digests were fine but nothing was actually signed.
	if !sawSignature {
		return fmt.Errorf("RPM signature not verified, package may be unsigned: %s", rpmOut)
	}
	return nil
}

// CheckRPMSigs takes a list of RPM file names/paths and runs CheckRPMSig on each,
// returning the Join of any errors encountered (if any)
func CheckRPMSigs(rpmFiles []string) error {
	if len(rpmFiles) == 0 {
		return fmt.Errorf("list of RPM files to check signatures on is empty")
	}
	logrus.Infof("Checking files for RPM signatures")
	var errs []error
	for _, rpmFile := range rpmFiles {
		if err := CheckRPMSig(rpmFile); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
