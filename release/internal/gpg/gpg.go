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

package gpg

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
)

// PubKey takes a GPG key ID and fetches the ascii-armored GPG public key
func PubKey(runner command.CommandRunner, gpgKeyID string) (string, error) {
	logrus.Debugf("Getting ascii-armored public key for GPG key %s", gpgKeyID)

	cmdArgs := []string{"--armor", "--export", gpgKeyID}
	logrus.Debugf("Running gpg with args %s", strings.Join(cmdArgs, " "))
	gpgOut, err := runner.Run("gpg", cmdArgs, nil)
	if err != nil {
		return "", fmt.Errorf("exporting gpg key: %w", err)
	}
	return gpgOut, nil
}

// ExportPubKeyFile writes the ascii-armored public key for gpgKeyID into dir
// as "<prefix>-<YYYY-MM-DD>.asc", dated by the key's creation date, and returns
// the file name.
//
// The date is part of the name so that replacing the signing key publishes a new
// URL rather than silently changing the contents of an existing one: clients pin
// the gpgkey URL in their .repo file, and mirrors and CDNs cache by URL, so a
// changed-in-place key file is both a cache hazard and indistinguishable from
// tampering.
func ExportPubKeyFile(runner command.CommandRunner, gpgKeyID, dir, prefix string) (string, error) {
	pubKey, err := PubKey(runner, gpgKeyID)
	if err != nil {
		return "", fmt.Errorf("unable to export public key for GPG key %s: %w", gpgKeyID, err)
	}
	if !strings.Contains(pubKey, "BEGIN PGP PUBLIC KEY BLOCK") {
		return "", fmt.Errorf("gpg has no public key for %s: check the key ID given by --gpg-key-id / GPG_KEY_ID", gpgKeyID)
	}
	created, err := KeyCreationDate(runner, gpgKeyID)
	if err != nil {
		return "", err
	}

	fileName := fmt.Sprintf("%s-%s.asc", prefix, created.UTC().Format(time.DateOnly))
	logrus.Infof("Exporting public key for GPG key %s to %s", gpgKeyID, fileName)
	// gpg emits the armored key without a trailing newline in some versions;
	// clients are happier with one, and it makes the file diff-friendly.
	if !strings.HasSuffix(pubKey, "\n") {
		pubKey += "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte(pubKey), 0o644); err != nil {
		return "", fmt.Errorf("unable to write public key file %s: %w", fileName, err)
	}
	return fileName, nil
}

// KeyCreationDate returns when the GPG key was created, taken from the
// machine-readable key listing.
func KeyCreationDate(runner command.CommandRunner, gpgKeyID string) (time.Time, error) {
	cmdArgs := []string{"--list-keys", "--with-colons", gpgKeyID}
	gpgOut, err := runner.Run("gpg", cmdArgs, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("unable to list GPG key %s: %w", gpgKeyID, err)
	}
	for _, line := range strings.Split(gpgOut, "\n") {
		fields := strings.Split(line, ":")
		// Colon-listing record: type, validity, key length, algorithm, key ID,
		// creation date. See gpg's DETAILS documentation.
		if len(fields) < 6 || fields[0] != "pub" {
			continue
		}
		created, err := parseGPGDate(fields[5])
		if err != nil {
			return time.Time{}, fmt.Errorf("unable to read creation date of GPG key %s: %w", gpgKeyID, err)
		}
		return created, nil
	}
	return time.Time{}, fmt.Errorf("gpg reported no public key for %s: check the key ID given by --gpg-key-id / GPG_KEY_ID", gpgKeyID)
}

// parseGPGDate reads a date from a gpg colon listing, which gives either seconds
// since the epoch or an ISO 8601 basic timestamp depending on the gpg version.
func parseGPGDate(field string) (time.Time, error) {
	if field == "" {
		return time.Time{}, fmt.Errorf("date is empty")
	}
	if seconds, err := strconv.ParseInt(field, 10, 64); err == nil {
		return time.Unix(seconds, 0).UTC(), nil
	}
	parsed, err := time.Parse("20060102T150405", field)
	if err != nil {
		return time.Time{}, fmt.Errorf("date %q is neither seconds since the epoch nor an ISO 8601 timestamp", field)
	}
	return parsed.UTC(), nil
}

// DetachSign signs a file with the given GPG key, writing an ascii-armored
// detached signature to "<filePath>.asc" and returning that path. The signature
// is verified before returning, so a signature that cannot be checked fails here
// rather than in a client's package manager.
func DetachSign(runner command.CommandRunner, gpgKeyID, filePath string) (string, error) {
	sigPath := filePath + ".asc"
	logrus.Infof("Signing %s with GPG key %s", filePath, gpgKeyID)
	cmdArgs := []string{
		"--batch",
		// The file may already carry a signature from a previous run, or from
		// metadata downloaded from the existing published repository.
		"--yes",
		"--armor",
		"--detach-sign",
		"--local-user", gpgKeyID,
		"--output", sigPath,
		filePath,
	}
	if _, err := runner.Run("gpg", cmdArgs, nil); err != nil {
		return "", fmt.Errorf("unable to sign %s with GPG key %s: %w", filePath, gpgKeyID, err)
	}
	if _, err := runner.Run("gpg", []string{"--batch", "--verify", sigPath, filePath}, nil); err != nil {
		return "", fmt.Errorf("signed %s but its signature %s could not be verified: %w", filePath, sigPath, err)
	}
	return sigPath, nil
}

// RPMKeyring is a private RPM database, used to sign release packages and to
// verify the signatures afterwards. Every rpm command is pointed at it with the
// %_dbpath macro, so a release never reads or writes the host's RPM state: the
// public keyring path (%_keyringpath) is derived from %_dbpath, which puts the
// imported signing key inside this database too.
//
// Signing and verifying read two different keyrings. rpmsign signs with the
// secret key from the *GPG* keyring, while rpmkeys verifies against public keys
// imported into the *RPM* keyring, so signing succeeds even when the matching
// public key was never imported. ImportGPGKey bridges the two.
type RPMKeyring struct {
	dbPath string
	runner command.CommandRunner

	supportsRPMV4 func() bool
}

// NewRPMKeyring returns a keyring backed by a database under dbPath, which
// should be a scratch directory (e.g. under the release tmp directory) rather
// than the host's RPM database. The database files themselves are created by
// the first rpm command that writes to it, so there is no initdb step.
func NewRPMKeyring(runner command.CommandRunner, dbPath string) (*RPMKeyring, error) {
	if err := os.MkdirAll(dbPath, utils.DirPerms); err != nil {
		return nil, fmt.Errorf("unable to create RPM database directory %s: %w", dbPath, err)
	}
	logrus.Debugf("Using private RPM database at %s", dbPath)
	keyring := &RPMKeyring{dbPath: dbPath, runner: runner}
	keyring.supportsRPMV4 = sync.OnceValue(keyring.rpmsignSupportsRPMV4)
	return keyring, nil
}

// rpmArgs prefixes command arguments with the macro definition that redirects an
// rpm command at this keyring. Every rpm command this package runs goes through
// it; rpmsign does not read the database, but is pointed at it anyway so that no
// invocation can fall back to the host's configuration.
func (k *RPMKeyring) rpmArgs(args ...string) []string {
	return append([]string{"-D", fmt.Sprintf("%%_dbpath %s", k.dbPath)}, args...)
}

// ImportGPGKey imports the public half of a GPG signing key into the keyring, so
// that signatures made with that key can be verified. Call it before
// CheckRPMSigs; without it every package verifies as NOKEY.
func (k *RPMKeyring) ImportGPGKey(gpgKeyID string) error {
	pubKey, err := PubKey(k.runner, gpgKeyID)
	if err != nil {
		return fmt.Errorf("unable to export public key for GPG key %s: %w", gpgKeyID, err)
	}
	// gpg exits 0 and returns nothing when asked to export a key it does not
	// have, so an empty export is the only signal that the key ID is wrong.
	if !strings.Contains(pubKey, "BEGIN PGP PUBLIC KEY BLOCK") {
		return fmt.Errorf("gpg has no public key for %s: check the key ID given by --gpg-key-id / GPG_KEY_ID "+
			"and that the key is in the GPG keyring (gpg --list-keys %s)", gpgKeyID, gpgKeyID)
	}

	keyFile := filepath.Join(k.dbPath, "signing-key.asc")
	if err := os.WriteFile(keyFile, []byte(pubKey), 0o600); err != nil {
		return fmt.Errorf("unable to write public key for GPG key %s to %s: %w", gpgKeyID, keyFile, err)
	}
	logrus.Infof("Importing public key for GPG key %s into RPM database %s", gpgKeyID, k.dbPath)
	if _, err := k.runner.Run("rpmkeys", k.rpmArgs("--import", keyFile), nil); err != nil {
		return fmt.Errorf("unable to import public key for GPG key %s into RPM database %s: %w", gpgKeyID, k.dbPath, err)
	}
	return nil
}

// SignRPMFiles takes a GPG key ID whose secret key must be in the GPG keyring
// and uses it to sign a list of RPM files.
func (k *RPMKeyring) SignRPMFiles(gpgKeyID string, rpmFiles []string) error {
	if len(rpmFiles) == 0 {
		return fmt.Errorf("list of RPM files to sign is empty")
	}
	filteredRpmFiles, err := utils.FilterRegularFiles(rpmFiles)
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
	cmdArgs := k.signArgs(gpgKeyID, filteredRpmFiles)
	logrus.Debugf("Running rpmsign with args %s", strings.Join(cmdArgs, " "))
	if _, err := k.runner.Run("rpmsign", cmdArgs, nil); err != nil {
		return fmt.Errorf("unable to sign RPM files: %w", err)
	}
	return nil
}

// signArgs builds the rpmsign arguments for signing the given files. rpm 4 and
// rpm 6 disagree on all three of the naming, the signing binary and the
// signature format, so the arguments accommodate both rather than assuming the
// version the release agents happen to have (4.17).
func (k *RPMKeyring) signArgs(gpgKeyID string, rpmFiles []string) []string {
	// The macro naming the signing key was renamed: rpm 4 reads %_gpg_name, rpm 6
	// reads %_openpgp_sign_id, and each ignores the other's. Define both.
	args := k.rpmArgs(
		"-D", fmt.Sprintf("%%_gpg_name %s", gpgKeyID),
		"-D", fmt.Sprintf("%%_openpgp_sign_id %s", gpgKeyID),
	)
	// rpm 4 shells out to %__gpg, which Debian and Ubuntu build as /usr/bin/gpg2 —
	// a path their gnupg package does not install, so signing fails to exec it.
	if gpgPath, err := exec.LookPath("gpg"); err == nil {
		args = append(args, "-D", fmt.Sprintf("%%__gpg %s", gpgPath))
	}
	args = append(args, "--resign")
	// --rpmv4 keeps signatures backwards compatible on rpm 6, which otherwise
	// writes v6 header signatures. Only rpm 6 has the option; 4.17 and 4.20 reject
	// it outright and write v4 signatures anyway.
	if k.supportsRPMV4() {
		args = append(args, "--rpmv4")
	}
	return append(args, rpmFiles...)
}

// rpmsignSupportsRPMV4 reports whether the installed rpmsign accepts --rpmv4. It
// asks rpmsign rather than comparing versions, so a version that gains or loses
// the option needs no change here.
func (k *RPMKeyring) rpmsignSupportsRPMV4() bool {
	out, err := k.runner.Run("rpmsign", []string{"--help"}, nil)
	if err != nil {
		// Signing itself reports a usable error if rpmsign is missing or broken;
		// here, assume the option is absent rather than fail the help probe.
		logrus.WithError(err).Debug("Could not ask rpmsign for its options, assuming --rpmv4 is unsupported")
		return false
	}
	return strings.Contains(out, "--rpmv4")
}

// RPMSigCheckError reports that one RPM package failed signature validation.
// It keeps the individual problems and the raw rpmkeys output rather than only
// an exit status, so callers can explain *why* a package failed and can group
// identical failures across many packages instead of repeating one opaque line
// per package.
type RPMSigCheckError struct {
	// File is the package that failed.
	File string
	// Problems is every distinct reason the package failed, in the order
	// rpmkeys reported them.
	Problems []rpmSigProblem
	// Output is the raw `rpmkeys --checksig -v` output, kept for logging.
	Output string
}

// Error reports the file, every cause, and the remedy for each cause, on a
// single line: it ends up in a log formatter's error field, which escapes
// embedded newlines.
func (e *RPMSigCheckError) Error() string {
	return fmt.Sprintf("%s: %s", e.File, strings.Join(problemStrings(e.Problems), "; "))
}

// rpmSigProblem is one reason a package failed its signature check, together
// with the action an operator can take to fix it.
type rpmSigProblem struct {
	// cause is deliberately independent of the file name so that identical
	// failures across many packages can be grouped by it.
	cause string
	// detail carries any extra text rpmkeys printed with the failing check.
	detail string
	// remedy says what to do about the cause; empty when there is nothing
	// generic worth suggesting.
	remedy string
}

func (p rpmSigProblem) String() string {
	if p.detail == "" {
		return p.cause
	}
	return fmt.Sprintf("%s %s", p.cause, p.detail)
}

// CheckRPMSig runs `rpmkeys --checksig -v` on an RPM file and reports whether
// its signature and digests all verified. Also run lstat on the file to ensure
// it exists before we shell out.
//
// The verbose form is used because the terse form reduces every failure to
// "digests SIGNATURES NOT OK", which says nothing about which check failed or
// which key was involved; the verbose form names the failing check and the key
// ID. rpmkeys exits non-zero for any failed check and writes that detail to
// *stdout*, leaving stderr empty, so the output is parsed whether or not the
// command exited cleanly — treating a non-zero exit as the whole story throws
// away the only useful diagnostic there is.
//
// Failures are returned as *RPMSigCheckError; see CheckRPMSigs, which groups
// them.
func (k *RPMKeyring) CheckRPMSig(rpmFile string) error {
	logrus.Debugf("Checking file %s for RPM signature", rpmFile)
	if _, err := os.Lstat(rpmFile); err != nil {
		return fmt.Errorf("could not validate rpm file exists: %w", err)
	}
	rpmOut, runErr := k.runner.Run("rpmkeys", k.rpmArgs("--checksig", "--verbose", rpmFile), nil)
	logrus.WithField("file", rpmFile).Debugf("rpmkeys --checksig -v output:\n%s", rpmOut)

	checks := parseRPMSigChecks(rpmOut)
	problems := rpmSigProblems(checks)
	switch {
	case len(checks) == 0:
		// rpmkeys reported no checks at all, so there is nothing to classify:
		// either the file is not a readable RPM package or rpmkeys itself
		// failed to run. Its exit status is the only signal available.
		problems = []rpmSigProblem{{
			cause:  "rpmkeys reported no signature or digest checks, so the file is probably not a readable RPM package",
			detail: rpmkeysExitDetail(runErr),
			remedy: "check the file is a complete RPM package and that rpmkeys works: " + k.checkSigCommand(rpmFile),
		}}
	case len(problems) == 0 && runErr != nil:
		// Every check rpmkeys printed passed, yet it still failed. Don't claim
		// the package is good; surface the mismatch with the raw output.
		problems = []rpmSigProblem{{
			cause:  "rpmkeys failed but every check it reported passed",
			detail: rpmkeysExitDetail(runErr),
			remedy: "run by hand to see the full output: " + k.checkSigCommand(rpmFile),
		}}
	case len(problems) == 0:
		return nil
	}

	// Logged at debug only: a release signs every package with one key in one
	// operation, so a failure normally repeats for all of them. CheckRPMSigs
	// logs the grouped report that an operator actually reads.
	logrus.WithField("file", rpmFile).Debugf("RPM signature/digest check failed: %s",
		strings.Join(problemStrings(problems), "; "))
	return &RPMSigCheckError{File: rpmFile, Problems: problems, Output: rpmOut}
}

// checkSigCommand renders the command an operator can run to reproduce a check
// against this keyring, rather than against the host's RPM database.
func (k *RPMKeyring) checkSigCommand(rpmFile string) string {
	return fmt.Sprintf(`rpmkeys -D "%%_dbpath %s" --checksig -v %s`, k.dbPath, rpmFile)
}

// rpmkeysExitDetail renders how rpmkeys exited, for inclusion in a problem's
// detail. The runner already appends stderr to the error, which is empty for
// a plain check failure, so trim it back to something readable.
func rpmkeysExitDetail(runErr error) string {
	if runErr == nil {
		return "(rpmkeys exited successfully)"
	}
	return fmt.Sprintf("(rpmkeys: %s)", strings.Trim(strings.TrimSpace(runErr.Error()), ":"))
}

func problemStrings(problems []rpmSigProblem) []string {
	out := make([]string, 0, len(problems))
	for _, p := range problems {
		s := p.String()
		if p.remedy != "" {
			s += "; fix: " + p.remedy
		}
		out = append(out, s)
	}
	return out
}

// rpmSigCheck is one "<description>: <result> [<detail>]" line of verbose
// rpmkeys output, e.g.
//
//	Header OpenPGP V4 RSA/SHA512 signature, key ID ac5957cfb5a392c6: NOKEY
//	Header OpenPGP V4 RSA/SHA512 signature, key fingerprint: 244f1c36...: OK
//	Header SHA256 digest: BAD (Expected 3797... != 78be...)
type rpmSigCheck struct {
	description string
	result      string // upper-cased, e.g. "OK", "NOKEY", "BAD", "NOTFOUND"
	detail      string
}

// parseRPMSigChecks pulls the per-check results out of the verbose output of
// `rpmkeys --checksig -v` for a single package.
func parseRPMSigChecks(rpmOut string) []rpmSigCheck {
	var checks []rpmSigCheck
	for i, line := range strings.Split(rpmOut, "\n") {
		// rpmkeys echoes the package path back on the first line ("<path>:")
		// and indents the checks beneath it. Skipping that line keeps a path
		// which happens to contain something like ": OK" from being read as a
		// check result.
		if i == 0 {
			continue
		}
		if check, ok := splitRPMSigCheck(line); ok {
			checks = append(checks, check)
		}
	}
	return checks
}

// rpmSigResults are the result words rpm prints for a signature or digest
// check. They are used to find where the description ends, because both halves
// of a check line can contain a colon: rpm 6 writes "..., key fingerprint:
// <fpr>: OK", and a detail can read "BAD (package: tag 5121: invalid hex)".
var rpmSigResults = map[string]bool{
	"OK":         true,
	"BAD":        true,
	"NOKEY":      true,
	"NOTTRUSTED": true,
	"UNTRUSTED":  true,
	"NOTFOUND":   true,
	"MISSING":    true,
	"DISABLED":   true,
	"FAIL":       true,
	"UNKNOWN":    true,
}

// splitRPMSigCheck splits one output line into its description, result and
// trailing detail. It anchors on the last colon that is followed by a known
// result word, falling back to the last colon in the line so that a result rpm
// grows in a later version is still reported (as an unrecognised one) rather
// than silently dropped.
func splitRPMSigCheck(line string) (rpmSigCheck, bool) {
	var lastColon = -1
	for i := len(line) - 1; i >= 0; i-- {
		if line[i] != ':' {
			continue
		}
		if lastColon < 0 {
			lastColon = i
		}
		if fields := strings.Fields(line[i+1:]); len(fields) > 0 && rpmSigResults[strings.ToUpper(fields[0])] {
			return newRPMSigCheck(line[:i], fields)
		}
	}
	if lastColon < 0 {
		return rpmSigCheck{}, false
	}
	fields := strings.Fields(line[lastColon+1:])
	if len(fields) == 0 {
		return rpmSigCheck{}, false
	}
	return newRPMSigCheck(line[:lastColon], fields)
}

func newRPMSigCheck(description string, resultFields []string) (rpmSigCheck, bool) {
	description = strings.TrimSpace(description)
	if description == "" {
		return rpmSigCheck{}, false
	}
	return rpmSigCheck{
		description: description,
		result:      strings.ToUpper(resultFields[0]),
		detail:      strings.Join(resultFields[1:], " "),
	}, true
}

// keyIDPattern matches the key rpmkeys names in a signature check line. rpm 4
// prints "key ID <id>", rpm 6 prints "key fingerprint: <fingerprint>".
var keyIDPattern = regexp.MustCompile(`(?i)key (?:id|fingerprint):? ([0-9a-f]+)`)

// rpmSigProblems classifies parsed checks into distinct failures. An empty
// result means every check rpmkeys reported passed *and* one of them was a
// signature: an unsigned package still passes its digest checks and exits zero,
// so "no failures" alone does not mean the package is signed.
func rpmSigProblems(checks []rpmSigCheck) []rpmSigProblem {
	var problems []rpmSigProblem
	seen := make(map[string]bool)
	addProblem := func(p rpmSigProblem) {
		if seen[p.String()] {
			return
		}
		seen[p.String()] = true
		problems = append(problems, p)
	}

	var sawVerifiedSignature bool
	for _, c := range checks {
		isSignature := strings.Contains(strings.ToLower(c.description), "signature")
		switch c.result {
		case "OK":
			if isSignature {
				sawVerifiedSignature = true
			}
		case "NOTFOUND":
			// The package simply does not carry this digest or signature type.
			// rpmkeys lists it for completeness; it is not a failure.
		case "NOKEY":
			addProblem(rpmSigProblem{
				cause: fmt.Sprintf("signed by key %s, whose public key is not in the RPM keyring, so the signature could not be verified",
					describeSigKey(c)),
				remedy: "the release imports the public key for --gpg-key-id / GPG_KEY_ID into its own RPM keyring before verifying, " +
					"so check that key ID names the same key the packages were signed with",
			})
		case "NOTTRUSTED", "UNTRUSTED":
			addProblem(rpmSigProblem{
				cause: fmt.Sprintf("signed by key %s, which is in the RPM keyring but is not trusted",
					describeSigKey(c)),
				remedy: "re-import the signing key's public key into the RPM keyring, or sign with a trusted key",
			})
		case "BAD":
			if isSignature {
				addProblem(rpmSigProblem{
					cause: fmt.Sprintf("signature from key %s does not match the package contents; the package was modified after it was signed",
						describeSigKey(c)),
					detail: c.detail,
					remedy: "rebuild and re-sign the package; make sure nothing rewrites it after signing",
				})
				continue
			}
			addProblem(rpmSigProblem{
				cause:  fmt.Sprintf("%s does not match the package contents; the package is corrupt or truncated", c.description),
				detail: c.detail,
				remedy: "rebuild the package and copy it again",
			})
		default:
			addProblem(rpmSigProblem{
				cause:  fmt.Sprintf("%s reported an unrecognised result %q", c.description, c.result),
				detail: c.detail,
				remedy: "run rpmkeys --checksig -v on the package to see the full output",
			})
		}
	}

	if len(problems) == 0 && !sawVerifiedSignature && len(checks) > 0 {
		problems = append(problems, rpmSigProblem{
			cause:  "package carries no OpenPGP signature: its digests verified, but nothing was signed",
			remedy: "sign the package (rpmsign --resign) before publishing it",
		})
	}
	return problems
}

// describeSigKey names the key in a signature check line, falling back to the
// whole description when rpmkeys did not print a key ID.
func describeSigKey(c rpmSigCheck) string {
	if m := keyIDPattern.FindStringSubmatch(c.description); m != nil {
		return m[1]
	}
	return fmt.Sprintf("(unidentified; %s)", c.description)
}

// CheckRPMSigs runs CheckRPMSig over a list of RPM files. Because a whole
// release's packages are normally signed with one key in one operation, a
// failure usually affects every package for the same reason; failures are
// therefore grouped by cause and reported once per cause with the affected
// packages, instead of returning one indistinguishable error per package.
//
// The grouped report is logged line by line (log formatters escape embedded
// newlines, which makes a multi-line error string unreadable) and the returned
// error is a compact single-line summary.
func (k *RPMKeyring) CheckRPMSigs(rpmFiles []string) error {
	if len(rpmFiles) == 0 {
		return fmt.Errorf("list of RPM files to check signatures on is empty")
	}
	logrus.Infof("Checking %d file(s) for RPM signatures", len(rpmFiles))

	var sigFailures []*RPMSigCheckError
	var otherErrs []error
	for _, rpmFile := range rpmFiles {
		err := k.CheckRPMSig(rpmFile)
		if err == nil {
			continue
		}
		var sigErr *RPMSigCheckError
		if errors.As(err, &sigErr) {
			sigFailures = append(sigFailures, sigErr)
			continue
		}
		otherErrs = append(otherErrs, err)
	}
	if len(sigFailures) == 0 && len(otherErrs) == 0 {
		return nil
	}

	groups := groupRPMSigFailures(sigFailures)
	failed := len(sigFailures) + len(otherErrs)
	logrus.Errorf("%d of %d RPM package(s) failed signature validation:", failed, len(rpmFiles))
	for _, g := range groups {
		logrus.Errorf("  %d package(s): %s", len(g.files), g.problem.String())
		if g.problem.remedy != "" {
			logrus.Errorf("    fix: %s", g.problem.remedy)
		}
		logrus.Errorf("    affected: %s", describeFiles(g.files, maxFilesLogged))
	}
	for _, err := range otherErrs {
		logrus.Errorf("  %s", err)
	}
	if len(sigFailures) > 0 {
		// One package's raw output, as a worked example: the causes above are a
		// summary of it, and anything they could not classify is visible here.
		// Logged line by line because log formatters escape embedded newlines.
		logrus.Errorf("  rpmkeys --checksig -v %s reported:", sigFailures[0].File)
		for _, line := range strings.Split(strings.TrimSpace(sigFailures[0].Output), "\n") {
			logrus.Errorf("    %s", strings.TrimSpace(line))
		}
	}

	return fmt.Errorf("%d of %d RPM package(s) failed signature validation: %s",
		failed, len(rpmFiles), summarizeRPMSigFailures(groups, otherErrs))
}

// maxFilesLogged / maxFilesSummarized cap how many package names are listed per
// cause, in the log and in the returned error respectively.
const (
	maxFilesLogged     = 5
	maxFilesSummarized = 2
)

// rpmSigFailureGroup is one cause plus the packages that failed because of it.
type rpmSigFailureGroup struct {
	problem rpmSigProblem
	files   []string
}

// groupRPMSigFailures collapses per-package failures into one entry per cause,
// keeping the order in which causes were first seen so the report is stable.
func groupRPMSigFailures(failures []*RPMSigCheckError) []rpmSigFailureGroup {
	var groups []rpmSigFailureGroup
	index := make(map[string]int)
	for _, f := range failures {
		for _, p := range f.Problems {
			key := p.String()
			if i, ok := index[key]; ok {
				groups[i].files = append(groups[i].files, f.File)
				continue
			}
			index[key] = len(groups)
			groups = append(groups, rpmSigFailureGroup{problem: p, files: []string{f.File}})
		}
	}
	return groups
}

// summarizeRPMSigFailures renders the grouped causes as one bracketed
// single-line summary. It stays on one line deliberately: this text ends up in
// a log formatter's error field, which escapes embedded newlines.
func summarizeRPMSigFailures(groups []rpmSigFailureGroup, otherErrs []error) string {
	parts := make([]string, 0, len(groups)+len(otherErrs))
	for _, g := range groups {
		part := g.problem.String()
		if g.problem.remedy != "" {
			part += "; fix: " + g.problem.remedy
		}
		parts = append(parts, fmt.Sprintf("[%d package(s): %s; affected: %s]",
			len(g.files), part, describeFiles(g.files, maxFilesSummarized)))
	}
	for _, err := range otherErrs {
		parts = append(parts, fmt.Sprintf("[%s]", err))
	}
	return strings.Join(parts, " ")
}

// describeFiles renders up to max package names, noting how many were elided.
// Release RPM paths share a long output-directory prefix, so it is factored out
// and reported once instead of repeated on every name.
func describeFiles(files []string, max int) string {
	prefix := commonDirPrefix(files)
	if prefix == "" {
		return listFiles(files, max)
	}
	names := make([]string, len(files))
	for i, f := range files {
		rel, err := filepath.Rel(prefix, f)
		if err != nil {
			rel = f
		}
		names[i] = rel
	}
	return fmt.Sprintf("under %s: %s", prefix, listFiles(names, max))
}

// listFiles renders up to max names, noting how many were elided.
func listFiles(names []string, max int) string {
	if len(names) <= max {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s (and %d more)", strings.Join(names[:max], ", "), len(names)-max)
}

// commonDirPrefix returns the longest directory path shared by every file, or
// "" when they share nothing worth factoring out.
func commonDirPrefix(files []string) string {
	if len(files) < 2 {
		return ""
	}
	shared := strings.Split(filepath.Dir(files[0]), string(filepath.Separator))
	for _, f := range files[1:] {
		segments := strings.Split(filepath.Dir(f), string(filepath.Separator))
		if len(segments) < len(shared) {
			shared = shared[:len(segments)]
		}
		for i := range shared {
			if segments[i] != shared[i] {
				shared = shared[:i]
				break
			}
		}
	}
	prefix := strings.Join(shared, string(filepath.Separator))
	if prefix == "" || prefix == "." || prefix == string(filepath.Separator) {
		return ""
	}
	return prefix
}
