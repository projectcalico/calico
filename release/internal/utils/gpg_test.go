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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The functions under test shell out to gpg / rpmbuild / rpmsign / rpmkeys and
// inherit the process environment (command.Run passes a nil env, so the child
// process sees os.Environ()). We exploit that to run everything inside a
// sandbox: GNUPGHOME is redirected to a throwaway keyring, and HOME points at a
// directory whose .rpmmacros sends rpm at an isolated database. This keeps the
// tests hermetic (no host keyring or rpm db is touched) and root-free (the
// public key is imported into the private db rather than the system one).

// requireCmds skips the test unless every named executable is on PATH.
func requireCmds(t *testing.T, cmds ...string) {
	t.Helper()
	for _, c := range cmds {
		if _, err := exec.LookPath(c); err != nil {
			t.Skipf("required command %q not found on PATH; skipping", c)
		}
	}
}

// runSetup executes a scaffolding command (key/RPM/db setup), failing the test
// on error. It is deliberately separate from the functions under test.
func runSetup(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("setup command %q %v failed: %v\n%s", name, args, err, out)
	}
}

// signingEnv holds the isolated GPG / RPM state for a test.
type signingEnv struct {
	keyID  string
	topDir string // rpmbuild _topdir
}

// newSigningEnv creates an isolated GnuPG home and RPM database, generates a
// throwaway signing key, and imports its public key into the isolated RPM db.
// All state lives under t.TempDir(); GNUPGHOME and HOME are redirected via
// t.Setenv so the functions under test operate entirely within the sandbox.
func newSigningEnv(t *testing.T) *signingEnv {
	t.Helper()
	requireCmds(t, "gpg", "rpmbuild", "rpmsign", "rpmkeys", "rpmdb")

	base := t.TempDir()
	gnupgHome := filepath.Join(base, "gnupg")
	home := filepath.Join(base, "home")
	dbPath := filepath.Join(base, "rpmdb")
	for _, d := range []string{gnupgHome, home, dbPath} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	t.Setenv("GNUPGHOME", gnupgHome)
	t.Setenv("HOME", home)

	// Point rpm at the isolated database so we can import a public key and
	// verify signatures without root or touching the host rpm db.
	if err := os.WriteFile(filepath.Join(home, ".rpmmacros"),
		[]byte("%_dbpath "+dbPath+"\n"), 0o644); err != nil {
		t.Fatalf("write .rpmmacros: %v", err)
	}

	// Generate an unprotected RSA key non-interactively.
	keyParams := filepath.Join(base, "keyparams")
	if err := os.WriteFile(keyParams, []byte(strings.Join([]string{
		"%no-protection",
		"Key-Type: RSA",
		"Key-Length: 2048",
		"Name-Real: Calico Release Test Key",
		"Name-Email: release-test@example.com",
		"Expire-Date: 0",
		"%commit",
		"",
	}, "\n")), 0o600); err != nil {
		t.Fatalf("write key params: %v", err)
	}
	runSetup(t, "gpg", "--batch", "--gen-key", keyParams)

	env := &signingEnv{
		keyID:  gpgKeyID(t, "release-test@example.com"),
		topDir: filepath.Join(base, "rpmbuild"),
	}

	// Initialize the isolated rpm db and import the public key so signature
	// verification can succeed.
	runSetup(t, "rpmdb", "--initdb")
	pubPath := filepath.Join(base, "pub.asc")
	runSetup(t, "gpg", "--armor", "--output", pubPath, "--export", env.keyID)
	runSetup(t, "rpmkeys", "--import", pubPath)

	return env
}

// gpgKeyID returns the long ID of the key matching the given identity.
func gpgKeyID(t *testing.T, identity string) string {
	t.Helper()
	out, err := exec.Command("gpg", "--list-keys", "--with-colons", identity).CombinedOutput()
	if err != nil {
		t.Fatalf("gpg --list-keys failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, ":")
		if len(f) > 4 && f[0] == "pub" {
			return f[4]
		}
	}
	t.Fatalf("could not find key ID in gpg output:\n%s", out)
	return ""
}

// buildTestRPM builds a minimal, initially-unsigned noarch RPM under the
// isolated topDir and returns the path to the built package.
func (e *signingEnv) buildTestRPM(t *testing.T, name string) string {
	t.Helper()
	for _, sub := range []string{"SPECS", "RPMS", "BUILD", "SOURCES", "SRPMS", "BUILDROOT"} {
		if err := os.MkdirAll(filepath.Join(e.topDir, sub), 0o755); err != nil {
			t.Fatalf("mkdir rpmbuild/%s: %v", sub, err)
		}
	}
	spec := filepath.Join(e.topDir, "SPECS", name+".spec")
	specContent := strings.Join([]string{
		"Name: " + name,
		"Version: 1.0",
		"Release: 1",
		"Summary: test package",
		"License: Apache-2.0",
		"BuildArch: noarch",
		"%description",
		"test package",
		"%files",
		"%changelog",
		"",
	}, "\n")
	if err := os.WriteFile(spec, []byte(specContent), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	runSetup(t, "rpmbuild", "--define", "_topdir "+e.topDir, "-bb", spec)

	rpmPath := filepath.Join(e.topDir, "RPMS", "noarch", name+"-1.0-1.noarch.rpm")
	if _, err := os.Stat(rpmPath); err != nil {
		t.Fatalf("expected built rpm at %s: %v", rpmPath, err)
	}
	return rpmPath
}

func TestGetGPGPubKey(t *testing.T) {
	env := newSigningEnv(t)

	t.Run("returns ascii-armored public key", func(t *testing.T) {
		key, err := GetGPGPubKey(env.keyID)
		if err != nil {
			t.Fatalf("GetGPGPubKey: unexpected error: %v", err)
		}
		if !strings.Contains(key, "BEGIN PGP PUBLIC KEY BLOCK") ||
			!strings.Contains(key, "END PGP PUBLIC KEY BLOCK") {
			t.Errorf("expected an ascii-armored public key block, got:\n%s", key)
		}
	})

	t.Run("unknown key yields no key material", func(t *testing.T) {
		// gpg exits 0 when asked to export an unknown key, returning nothing,
		// so GetGPGPubKey reports no error and an empty result.
		key, err := GetGPGPubKey("DEADBEEFDEADBEEF")
		if err != nil {
			t.Fatalf("GetGPGPubKey: unexpected error: %v", err)
		}
		if strings.Contains(key, "BEGIN PGP") {
			t.Errorf("expected no key material for unknown key, got:\n%s", key)
		}
	})
}

func TestSignRPMFiles(t *testing.T) {
	env := newSigningEnv(t)

	t.Run("signs an RPM so its signature verifies", func(t *testing.T) {
		rpm := env.buildTestRPM(t, "signme")

		if err := SignRPMFiles(env.keyID, []string{rpm}); err != nil {
			t.Fatalf("SignRPMFiles: unexpected error: %v", err)
		}
		// A freshly signed package, whose key we imported above, must verify.
		if err := CheckRPMSig(rpm); err != nil {
			t.Errorf("CheckRPMSig after signing: unexpected error: %v", err)
		}
	})

	t.Run("errors on a non-existent file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist.rpm")
		if err := SignRPMFiles(env.keyID, []string{missing}); err == nil {
			t.Fatal("SignRPMFiles: expected an error for a missing file, got nil")
		}
	})
}

func TestCheckRPMSig(t *testing.T) {
	env := newSigningEnv(t)

	t.Run("passes for a signed RPM", func(t *testing.T) {
		rpm := env.buildTestRPM(t, "goodsig")
		if err := SignRPMFiles(env.keyID, []string{rpm}); err != nil {
			t.Fatalf("SignRPMFiles: %v", err)
		}
		if err := CheckRPMSig(rpm); err != nil {
			t.Errorf("CheckRPMSig: unexpected error: %v", err)
		}
	})

	t.Run("errors on a non-existent file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nope.rpm")
		err := CheckRPMSig(missing)
		if err == nil {
			t.Fatal("CheckRPMSig: expected an error for a missing file, got nil")
		}
		if !strings.Contains(err.Error(), "unable to check RPM signature") {
			t.Errorf("CheckRPMSig: unexpected error message: %v", err)
		}
	})
}

func TestCheckRPMSigs(t *testing.T) {
	env := newSigningEnv(t)

	signed := func(name string) string {
		rpm := env.buildTestRPM(t, name)
		if err := SignRPMFiles(env.keyID, []string{rpm}); err != nil {
			t.Fatalf("SignRPMFiles(%s): %v", name, err)
		}
		return rpm
	}

	t.Run("nil for no files", func(t *testing.T) {
		if err := CheckRPMSigs(nil); err != nil {
			t.Errorf("CheckRPMSigs(nil): unexpected error: %v", err)
		}
	})

	t.Run("nil when every file is signed", func(t *testing.T) {
		rpms := []string{signed("multi1"), signed("multi2")}
		if err := CheckRPMSigs(rpms); err != nil {
			t.Errorf("CheckRPMSigs: unexpected error: %v", err)
		}
	})

	t.Run("aggregates one failure among good files", func(t *testing.T) {
		good := signed("mixedgood")
		bad := filepath.Join(t.TempDir(), "missing.rpm")
		err := CheckRPMSigs([]string{good, bad})
		if err == nil {
			t.Fatal("CheckRPMSigs: expected an error, got nil")
		}
		if n := strings.Count(err.Error(), "unable to check RPM signature"); n != 1 {
			t.Errorf("expected exactly 1 signature failure, got %d in: %v", n, err)
		}
	})

	t.Run("aggregates failures across multiple bad files", func(t *testing.T) {
		dir := t.TempDir()
		err := CheckRPMSigs([]string{
			filepath.Join(dir, "missing1.rpm"),
			filepath.Join(dir, "missing2.rpm"),
		})
		if err == nil {
			t.Fatal("CheckRPMSigs: expected an error, got nil")
		}
		// errors.Join surfaces every underlying failure.
		if n := strings.Count(err.Error(), "unable to check RPM signature"); n != 2 {
			t.Errorf("expected 2 aggregated failures, got %d in: %v", n, err)
		}
	})
}
