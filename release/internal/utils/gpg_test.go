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
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The functions under test shell out to gpg / rpmbuild / rpmsign / rpmkeys and
// inherit the process environment (command.Run passes a nil env, so the child
// process sees os.Environ()). We exploit that to run everything inside a
// sandbox: GNUPGHOME is redirected to a throwaway GPG keyring. RPMKeyring
// already isolates the RPM side by construction, so the tests point one at a
// temporary directory. This keeps the tests hermetic (no host keyring or rpm db
// is touched) and root-free.

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
	*RPMKeyring
	base   string
	keyID  string
	topDir string // rpmbuild _topdir
}

// newSigningEnv creates an isolated GnuPG home and a private RPM keyring,
// generates a throwaway signing key, and imports its public key into the
// keyring. All state lives under t.TempDir(); GNUPGHOME is redirected via
// t.Setenv so gpg operates entirely within the sandbox.
func newSigningEnv(t *testing.T) *signingEnv {
	t.Helper()
	requireCmds(t, "gpg", "rpmbuild", "rpmsign", "rpmkeys")

	base := t.TempDir()
	gnupgHome := filepath.Join(base, "gnupg")
	if err := os.MkdirAll(gnupgHome, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", gnupgHome, err)
	}
	t.Setenv("GNUPGHOME", gnupgHome)

	env := &signingEnv{
		base:   base,
		keyID:  genGPGKey(t, filepath.Join(base, "keyparams"), "Calico Release Test Key", "release-test@example.com"),
		topDir: filepath.Join(base, "rpmbuild"),
	}
	env.RPMKeyring = env.newKeyring(t, "rpmdb")
	if err := env.ImportGPGKey(env.keyID); err != nil {
		t.Fatalf("ImportGPGKey: %v", err)
	}
	return env
}

// newKeyring returns a keyring backed by a fresh database under the sandbox, so
// a test can compare one keyring against another.
func (e *signingEnv) newKeyring(t *testing.T, name string) *RPMKeyring {
	t.Helper()
	keyring, err := NewRPMKeyring(filepath.Join(e.base, name))
	if err != nil {
		t.Fatalf("NewRPMKeyring(%s): %v", name, err)
	}
	return keyring
}

// genGPGKey generates an unprotected RSA signing key non-interactively in the
// sandbox keyring and returns its long key ID. paramsPath must be unique per key.
// extraParams are appended to gpg's unattended key generation parameters, e.g.
// "Creation-Date: 20200101T000000" to pin when the key was created.
func genGPGKey(t *testing.T, paramsPath, name, email string, extraParams ...string) string {
	t.Helper()
	params := append([]string{
		"%no-protection",
		"Key-Type: RSA",
		"Key-Length: 2048",
		"Name-Real: " + name,
		"Name-Email: " + email,
		"Expire-Date: 0",
	}, extraParams...)
	params = append(params, "%commit", "")
	if err := os.WriteFile(paramsPath, []byte(strings.Join(params, "\n")), 0o600); err != nil {
		t.Fatalf("write key params: %v", err)
	}
	runSetup(t, "gpg", "--batch", "--gen-key", paramsPath)
	return gpgKeyID(t, email)
}

// newUnimportedKey generates a second signing key whose public half is
// deliberately *not* imported into the isolated RPM database, so packages signed
// with it can be signed but not verified (rpmkeys reports NOKEY).
func (e *signingEnv) newUnimportedKey(t *testing.T) string {
	t.Helper()
	return genGPGKey(t, filepath.Join(t.TempDir(), "keyparams-unimported"),
		"Calico Release Unimported Key", "release-unimported@example.com")
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

func TestGPGKeyCreationDate(t *testing.T) {
	env := newSigningEnv(t)

	t.Run("reads the creation date from the key", func(t *testing.T) {
		keyID := genGPGKey(t, filepath.Join(env.base, "keyparams-dated"),
			"Calico Release Dated Key", "release-dated@example.com", "Creation-Date: 20200102T030405")
		created, err := GPGKeyCreationDate(keyID)
		if err != nil {
			t.Fatalf("GPGKeyCreationDate: unexpected error: %v", err)
		}
		if got := created.UTC().Format("20060102"); got != "20200102" {
			t.Errorf("GPGKeyCreationDate = %s, want 20200102", got)
		}
	})

	t.Run("errors for a key gpg does not have", func(t *testing.T) {
		if _, err := GPGKeyCreationDate("DEADBEEFDEADBEEF"); err == nil {
			t.Error("GPGKeyCreationDate: expected an error for an unknown key, got nil")
		}
	})
}

func TestParseGPGDate(t *testing.T) {
	// gpg writes either seconds since the epoch or an ISO 8601 basic timestamp,
	// depending on its version.
	cases := map[string]struct {
		field   string
		want    string // YYYYMMDD, empty when an error is expected
		wantErr bool
	}{
		"epoch seconds": {field: "1577836800", want: "20200101"},
		"iso 8601":      {field: "20200102T030405", want: "20200102"},
		"empty":         {field: "", wantErr: true},
		"not a date":    {field: "sometime", wantErr: true},
		// A bare number is always seconds since the epoch, never a bare date.
		"all digits is epoch seconds": {field: "20200102", want: "19700822"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseGPGDate(tc.field)
			if tc.wantErr {
				if err == nil {
					t.Errorf("parseGPGDate(%q): expected an error, got %v", tc.field, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGPGDate(%q): unexpected error: %v", tc.field, err)
			}
			if formatted := got.UTC().Format("20060102"); formatted != tc.want {
				t.Errorf("parseGPGDate(%q) = %s, want %s", tc.field, formatted, tc.want)
			}
		})
	}
}

func TestExportGPGPubKeyFile(t *testing.T) {
	env := newSigningEnv(t)

	t.Run("names the file after the key's creation date", func(t *testing.T) {
		keyID := genGPGKey(t, filepath.Join(env.base, "keyparams-export"),
			"Calico Release Export Key", "release-export@example.com", "Creation-Date: 20200102T030405")
		dir := t.TempDir()

		name, err := ExportGPGPubKeyFile(keyID, dir, "calico-signing-key")
		if err != nil {
			t.Fatalf("ExportGPGPubKeyFile: unexpected error: %v", err)
		}
		if want := "calico-signing-key-2020-01-02.asc"; name != want {
			t.Errorf("ExportGPGPubKeyFile returned %q, want %q", name, want)
		}
		contents, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read exported key: %v", err)
		}
		if !strings.Contains(string(contents), "BEGIN PGP PUBLIC KEY BLOCK") ||
			!strings.HasSuffix(string(contents), "\n") {
			t.Errorf("expected a newline-terminated armored public key, got:\n%s", contents)
		}
	})

	t.Run("a replacement key gets a different file name", func(t *testing.T) {
		// The date in the name is what stops a new key from being published at
		// the URL clients already pinned for the old one.
		older := genGPGKey(t, filepath.Join(env.base, "keyparams-old"),
			"Calico Release Old Key", "release-old@example.com", "Creation-Date: 20200101T000000")
		newer := genGPGKey(t, filepath.Join(env.base, "keyparams-new"),
			"Calico Release New Key", "release-new@example.com", "Creation-Date: 20260101T000000")
		dir := t.TempDir()

		olderName, err := ExportGPGPubKeyFile(older, dir, "key")
		if err != nil {
			t.Fatalf("ExportGPGPubKeyFile(older): %v", err)
		}
		newerName, err := ExportGPGPubKeyFile(newer, dir, "key")
		if err != nil {
			t.Fatalf("ExportGPGPubKeyFile(newer): %v", err)
		}
		if olderName == newerName {
			t.Errorf("expected distinct file names for keys created on different dates, got %q twice", olderName)
		}
		// Both remain published: clients pinned to the old URL keep working.
		for _, name := range []string{olderName, newerName} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Errorf("expected %s to exist: %v", name, err)
			}
		}
	})

	t.Run("errors when gpg has no such key", func(t *testing.T) {
		if _, err := ExportGPGPubKeyFile("DEADBEEFDEADBEEF", t.TempDir(), "key"); err == nil {
			t.Error("ExportGPGPubKeyFile: expected an error for an unknown key, got nil")
		}
	})
}

func TestGPGDetachSign(t *testing.T) {
	env := newSigningEnv(t)

	// Stand in for a repository's repomd.xml.
	writeFile := func(t *testing.T, contents string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "repomd.xml")
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return path
	}

	t.Run("writes a verifiable detached signature", func(t *testing.T) {
		path := writeFile(t, "<repomd/>\n")

		sigPath, err := GPGDetachSign(env.keyID, path)
		if err != nil {
			t.Fatalf("GPGDetachSign: unexpected error: %v", err)
		}
		if sigPath != path+".asc" {
			t.Errorf("GPGDetachSign returned %q, want %q", sigPath, path+".asc")
		}
		sig, err := os.ReadFile(sigPath)
		if err != nil {
			t.Fatalf("read signature: %v", err)
		}
		if !strings.Contains(string(sig), "BEGIN PGP SIGNATURE") {
			t.Errorf("expected an ascii-armored detached signature, got:\n%s", sig)
		}
		// Verified independently of the check inside GPGDetachSign.
		runSetup(t, "gpg", "--batch", "--verify", sigPath, path)
	})

	t.Run("replaces an existing signature", func(t *testing.T) {
		// createrepo_c rewrites repomd.xml on every run, and metadata pulled from
		// the published repository can arrive with a stale signature alongside it,
		// so signing has to overwrite rather than refuse.
		path := writeFile(t, "<repomd>first</repomd>\n")
		if _, err := GPGDetachSign(env.keyID, path); err != nil {
			t.Fatalf("GPGDetachSign (first): %v", err)
		}
		if err := os.WriteFile(path, []byte("<repomd>second</repomd>\n"), 0o644); err != nil {
			t.Fatalf("rewrite %s: %v", path, err)
		}
		if _, err := GPGDetachSign(env.keyID, path); err != nil {
			t.Fatalf("GPGDetachSign (second): unexpected error: %v", err)
		}
		runSetup(t, "gpg", "--batch", "--verify", path+".asc", path)
	})

	t.Run("errors for a key gpg cannot sign with", func(t *testing.T) {
		path := writeFile(t, "<repomd/>\n")
		if _, err := GPGDetachSign("DEADBEEFDEADBEEF", path); err == nil {
			t.Error("GPGDetachSign: expected an error for an unknown key, got nil")
		}
	})

	t.Run("errors for a missing file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.xml")
		if _, err := GPGDetachSign(env.keyID, missing); err == nil {
			t.Error("GPGDetachSign: expected an error for a missing file, got nil")
		}
	})
}

func TestRPMKeyringImportGPGKey(t *testing.T) {
	env := newSigningEnv(t)

	t.Run("creates the database under the given directory", func(t *testing.T) {
		// newSigningEnv already imported into env's keyring; the database must
		// live where we asked for it and nowhere else.
		entries, err := os.ReadDir(filepath.Join(env.base, "rpmdb"))
		if err != nil {
			t.Fatalf("read rpm db dir: %v", err)
		}
		if len(entries) == 0 {
			t.Error("expected the import to populate the private RPM database directory")
		}
	})

	t.Run("keyrings are isolated from each other", func(t *testing.T) {
		// A package signed with a key imported into one keyring must not verify
		// against a second keyring, which proves rpmkeys really is reading the
		// per-keyring database rather than a shared one (the host's included).
		rpm := env.buildTestRPM(t, "isolated")
		if err := env.SignRPMFiles(env.keyID, []string{rpm}); err != nil {
			t.Fatalf("SignRPMFiles: %v", err)
		}
		if err := env.CheckRPMSig(rpm); err != nil {
			t.Fatalf("CheckRPMSig against the importing keyring: unexpected error: %v", err)
		}
		other := env.newKeyring(t, "other-rpmdb")
		err := other.CheckRPMSig(rpm)
		if err == nil {
			t.Fatal("CheckRPMSig against a keyring without the key: expected an error, got nil")
		}
		if !strings.Contains(err.Error(), "not in the RPM keyring") {
			t.Errorf("CheckRPMSig: unexpected error message: %v", err)
		}
	})

	t.Run("errors when gpg has no such key", func(t *testing.T) {
		// gpg exits 0 and exports nothing for an unknown key, so this has to be
		// caught here rather than surfacing later as NOKEY on every package.
		err := env.newKeyring(t, "empty-rpmdb").ImportGPGKey("DEADBEEFDEADBEEF")
		if err == nil {
			t.Fatal("ImportGPGKey: expected an error for an unknown key, got nil")
		}
		if !strings.Contains(err.Error(), "no public key for DEADBEEFDEADBEEF") {
			t.Errorf("ImportGPGKey: unexpected error message: %v", err)
		}
	})
}

// TestSignRPMFilesNoFiles verifies SignRPMFiles reports an error for an empty or
// nil file list rather than shelling out to rpmsign (which would otherwise fail
// with a confusing usage error). This needs no signing tooling, so it runs
// unconditionally, unlike the tests built on newSigningEnv.
func TestSignRPMFilesNoFiles(t *testing.T) {
	keyring := newTestKeyring(t)
	for name, files := range map[string][]string{
		"nil slice":   nil,
		"empty slice": {},
	} {
		t.Run(name, func(t *testing.T) {
			if err := keyring.SignRPMFiles("SOMEKEYID", files); err == nil {
				t.Errorf("SignRPMFiles(%s): expected an error for an empty file list, got nil", name)
			}
		})
	}
}

// newTestKeyring returns a keyring in a throwaway directory, for tests that
// short-circuit before running any rpm command.
func newTestKeyring(t *testing.T) *RPMKeyring {
	t.Helper()
	keyring, err := NewRPMKeyring(filepath.Join(t.TempDir(), "rpmdb"))
	if err != nil {
		t.Fatalf("NewRPMKeyring: %v", err)
	}
	return keyring
}

// TestSignRPMFilesAllFiltered verifies that when every provided path is
// non-regular (here, a directory) SignRPMFiles reports an error rather than
// invoking rpmsign with no packages. It short-circuits before shelling out, so
// it needs no signing tooling.
func TestSignRPMFilesAllFiltered(t *testing.T) {
	if err := newTestKeyring(t).SignRPMFiles("SOMEKEYID", []string{t.TempDir()}); err == nil {
		t.Error("SignRPMFiles: expected an error when no regular files remain, got nil")
	}
}

// TestSignArgs verifies the rpmsign invocation works on both rpm generations:
// the key is named by the macro each one reads, and --rpmv4 is passed only where
// it exists. rpm gained that option in 6.0, and passing it to the 4.17 on the
// release agents fails the whole signing step with "unknown option". The probe is
// replaced here so both cases are covered whatever rpm this machine has.
func TestSignArgs(t *testing.T) {
	keyring := newTestKeyring(t)
	original := rpmsignSupportsRPMV4
	t.Cleanup(func() { rpmsignSupportsRPMV4 = original })

	for _, tc := range []struct {
		name      string
		supported bool
	}{
		{name: "rpmsign accepts --rpmv4", supported: true},
		{name: "rpmsign rejects --rpmv4", supported: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rpmsignSupportsRPMV4 = func() bool { return tc.supported }
			args := keyring.signArgs("SOMEKEYID", []string{"one.rpm", "two.rpm"})

			if got := slices.Contains(args, "--rpmv4"); got != tc.supported {
				t.Errorf("--rpmv4 present = %v, want %v, in: %v", got, tc.supported, args)
			}
			// Whichever rpm runs this, one of the two key macros is the one it
			// reads, so both must be defined, and the rest of the invocation and
			// the packages it signs are the same either way.
			for _, want := range []string{
				"--resign",
				"%_gpg_name SOMEKEYID",
				"%_openpgp_sign_id SOMEKEYID",
			} {
				if !slices.Contains(args, want) {
					t.Errorf("expected %q in args, got: %v", want, args)
				}
			}
			if files := args[len(args)-2:]; !slices.Equal(files, []string{"one.rpm", "two.rpm"}) {
				t.Errorf("expected the packages last, got: %v", files)
			}
		})
	}
}

// TestSignArgsOverridesGPGPath verifies rpmsign is pointed at the gpg that is
// installed. rpm 4 on Debian and Ubuntu defaults %__gpg to /usr/bin/gpg2, which
// their gnupg package does not ship, and signing dies trying to exec it.
func TestSignArgsOverridesGPGPath(t *testing.T) {
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not on PATH; nothing to point rpmsign at")
	}
	args := newTestKeyring(t).signArgs("SOMEKEYID", []string{"one.rpm"})
	if want := "%__gpg " + gpgPath; !slices.Contains(args, want) {
		t.Errorf("expected %q in args, got: %v", want, args)
	}
}

func TestSignRPMFiles(t *testing.T) {
	env := newSigningEnv(t)

	t.Run("signs an RPM so its signature verifies", func(t *testing.T) {
		rpm := env.buildTestRPM(t, "signme")

		if err := env.SignRPMFiles(env.keyID, []string{rpm}); err != nil {
			t.Fatalf("SignRPMFiles: unexpected error: %v", err)
		}
		// A freshly signed package, whose key we imported above, must verify.
		if err := env.CheckRPMSig(rpm); err != nil {
			t.Errorf("CheckRPMSig after signing: unexpected error: %v", err)
		}
	})

	t.Run("errors on a non-existent file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist.rpm")
		if err := env.SignRPMFiles(env.keyID, []string{missing}); err == nil {
			t.Fatal("SignRPMFiles: expected an error for a missing file, got nil")
		}
	})

	t.Run("skips non-regular entries and signs the rest", func(t *testing.T) {
		// A directory mixed into the list is filtered out; the real RPM is
		// still signed and verifies.
		rpm := env.buildTestRPM(t, "mixedsign")
		aDir := t.TempDir()

		if err := env.SignRPMFiles(env.keyID, []string{aDir, rpm}); err != nil {
			t.Fatalf("SignRPMFiles: unexpected error: %v", err)
		}
		if err := env.CheckRPMSig(rpm); err != nil {
			t.Errorf("CheckRPMSig after signing: unexpected error: %v", err)
		}
	})
}

func TestCheckRPMSig(t *testing.T) {
	env := newSigningEnv(t)

	t.Run("passes for a signed RPM", func(t *testing.T) {
		rpm := env.buildTestRPM(t, "goodsig")
		if err := env.SignRPMFiles(env.keyID, []string{rpm}); err != nil {
			t.Fatalf("SignRPMFiles: %v", err)
		}
		if err := env.CheckRPMSig(rpm); err != nil {
			t.Errorf("CheckRPMSig: unexpected error: %v", err)
		}
	})

	t.Run("errors on a non-existent file", func(t *testing.T) {
		// CheckRPMSig lstat's the file before shelling out to rpmkeys, so a
		// missing file fails the existence check rather than the signature check.
		missing := filepath.Join(t.TempDir(), "nope.rpm")
		err := env.CheckRPMSig(missing)
		if err == nil {
			t.Fatal("CheckRPMSig: expected an error for a missing file, got nil")
		}
		if !strings.Contains(err.Error(), "could not validate rpm file exists") {
			t.Errorf("CheckRPMSig: unexpected error message: %v", err)
		}
	})

	t.Run("errors on an existing file that is not an RPM", func(t *testing.T) {
		// An existing but non-RPM file passes the lstat check and reaches
		// rpmkeys, which fails and surfaces the signature-check error.
		notRPM := filepath.Join(t.TempDir(), "plain.rpm")
		if err := os.WriteFile(notRPM, []byte("not an rpm"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		err := env.CheckRPMSig(notRPM)
		if err == nil {
			t.Fatal("CheckRPMSig: expected an error for a non-RPM file, got nil")
		}
		// rpmkeys prints no check results for a file it cannot read as a
		// package, and writes nothing to stderr, so the error has to say that
		// itself rather than passing on a bare exit status.
		if !strings.Contains(err.Error(), "not a readable RPM package") {
			t.Errorf("CheckRPMSig: unexpected error message: %v", err)
		}
		var sigErr *RPMSigCheckError
		if !errors.As(err, &sigErr) {
			t.Fatalf("CheckRPMSig: expected an *RPMSigCheckError, got %T", err)
		}
		if sigErr.File != notRPM {
			t.Errorf("CheckRPMSig: error names file %q, want %q", sigErr.File, notRPM)
		}
	})

	t.Run("reports an unsigned package as unsigned", func(t *testing.T) {
		// An unsigned package passes its digest checks and rpmkeys exits zero,
		// so the absence of a signature has to be detected from the output.
		rpm := env.buildTestRPM(t, "neversigned")
		err := env.CheckRPMSig(rpm)
		if err == nil {
			t.Fatal("CheckRPMSig: expected an error for an unsigned package, got nil")
		}
		if !strings.Contains(err.Error(), "no OpenPGP signature") {
			t.Errorf("CheckRPMSig: unexpected error message: %v", err)
		}
	})

	t.Run("reports a missing signing key as NOKEY, not a bare exit status", func(t *testing.T) {
		// Sign with a key whose public half was never imported into the RPM
		// keyring: the signature is intact but unverifiable. This is the failure
		// mode that previously surfaced only as "exit status 1".
		keyID := env.newUnimportedKey(t)
		rpm := env.buildTestRPM(t, "nokeysig")
		if err := env.SignRPMFiles(keyID, []string{rpm}); err != nil {
			t.Fatalf("SignRPMFiles: %v", err)
		}

		err := env.CheckRPMSig(rpm)
		if err == nil {
			t.Fatal("CheckRPMSig: expected an error when the signing key is not in the keyring, got nil")
		}
		msg := err.Error()
		if strings.Contains(msg, "exit status") {
			t.Errorf("CheckRPMSig: error should explain the failure, not just the exit status: %v", err)
		}
		for _, want := range []string{"not in the RPM keyring", "--gpg-key-id / GPG_KEY_ID"} {
			if !strings.Contains(msg, want) {
				t.Errorf("CheckRPMSig: error %q does not mention %q", msg, want)
			}
		}
		// The key ID rpmkeys named must be in the message so an operator can tell
		// which key needs importing. Match on the short (8 hex digit) key ID: rpm 4
		// reports that, rpm 6 reports the long one, and the short is its tail, so
		// this holds on either.
		if !strings.Contains(strings.ToLower(msg), strings.ToLower(keyID[len(keyID)-8:])) {
			t.Errorf("CheckRPMSig: error %q does not name signing key %s", msg, keyID)
		}
	})

	t.Run("reports a tampered package as a content mismatch", func(t *testing.T) {
		rpm := env.buildTestRPM(t, "tamperedsig")
		if err := env.SignRPMFiles(env.keyID, []string{rpm}); err != nil {
			t.Fatalf("SignRPMFiles: %v", err)
		}
		corruptPayload(t, rpm)

		err := env.CheckRPMSig(rpm)
		if err == nil {
			t.Fatal("CheckRPMSig: expected an error for a tampered package, got nil")
		}
		if !strings.Contains(err.Error(), "does not match the package contents") {
			t.Errorf("CheckRPMSig: unexpected error message: %v", err)
		}
	})
}

// corruptPayload overwrites bytes near the end of the file, inside the compressed
// payload, simulating a package modified after it was signed. The payload sits
// outside the signed header, so this breaks the payload digests while leaving the
// header signature itself verifiable.
func corruptPayload(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if _, err := f.WriteAt([]byte("XXXX"), info.Size()-20); err != nil {
		t.Fatalf("corrupt %s: %v", path, err)
	}
}

// TestParseRPMSigChecks exercises the parsing of verbose `rpmkeys --checksig -v`
// output in isolation, without shelling out. The formats covered are those
// emitted by rpm 4.x (Header/payload signature lines, "Signature" capitalised)
// and rpm 6.x ("OpenPGP ... signature", SHA3/NOTFOUND lines).
func TestParseRPMSigChecks(t *testing.T) {
	const rpm6NoKey = "pkg.rpm:\n" +
		"    Header OpenPGP V4 RSA/SHA512 signature, key ID ac5957cfb5a392c6: NOKEY\n" +
		"    Header SHA3-256 digest: NOTFOUND\n" +
		"    Header SHA256 digest: OK\n" +
		"    Payload SHA256 digest: OK\n"

	checks := parseRPMSigChecks(rpm6NoKey)
	if len(checks) != 4 {
		t.Fatalf("parseRPMSigChecks: got %d checks, want 4: %+v", len(checks), checks)
	}
	if checks[0].result != "NOKEY" {
		t.Errorf("first check result = %q, want NOKEY", checks[0].result)
	}
	if !strings.Contains(checks[0].description, "key ID ac5957cfb5a392c6") {
		t.Errorf("first check description = %q, want the key ID retained", checks[0].description)
	}

	// Both halves of a check line can contain a colon, so the result word is
	// what anchors the split.
	colonCases := map[string]rpmSigCheck{
		"    Header OpenPGP V4 RSA/SHA512 signature, key fingerprint: 244f1c36c157: OK": {
			description: "Header OpenPGP V4 RSA/SHA512 signature, key fingerprint: 244f1c36c157",
			result:      "OK",
		},
		"    Payload SHA512 digest: BAD (package: tag 5121: invalid hex)": {
			description: "Payload SHA512 digest",
			result:      "BAD",
			detail:      "(package: tag 5121: invalid hex)",
		},
	}
	for line, want := range colonCases {
		t.Run(strings.TrimSpace(line), func(t *testing.T) {
			got := parseRPMSigChecks("pkg.rpm:\n" + line)
			if len(got) != 1 {
				t.Fatalf("parseRPMSigChecks: got %d checks, want 1: %+v", len(got), got)
			}
			if got[0] != want {
				t.Errorf("parseRPMSigChecks:\n got %+v\nwant %+v", got[0], want)
			}
		})
	}
}

func TestRPMSigProblems(t *testing.T) {
	cases := map[string]struct {
		out         string
		wantCauses  []string // substrings expected in the reported causes
		wantNoIssue bool
	}{
		"verified signature (rpm 6)": {
			out: "pkg.rpm:\n" +
				"    Header OpenPGP V4 RSA/SHA512 signature, key ID ac5957cfb5a392c6: OK\n" +
				"    Header SHA3-256 digest: NOTFOUND\n" +
				"    Header SHA256 digest: OK\n" +
				"    Payload SHA256 digest: OK",
			wantNoIssue: true,
		},
		"verified signature (rpm 4)": {
			out: "pkg.rpm:\n" +
				"    Header V4 RSA/SHA256 Signature, key ID abcd1234: OK\n" +
				"    Header SHA1 digest: OK (5f2b)\n" +
				"    V4 RSA/SHA256 Signature, key ID abcd1234: OK\n" +
				"    MD5 digest: OK (1a2b)",
			wantNoIssue: true,
		},
		"missing key names the key once": {
			out: "pkg.rpm:\n" +
				"    Header V4 RSA/SHA256 Signature, key ID abcd1234: NOKEY\n" +
				"    Header SHA1 digest: OK (5f2b)\n" +
				"    V4 RSA/SHA256 Signature, key ID abcd1234: NOKEY\n" +
				"    MD5 digest: OK (1a2b)",
			wantCauses: []string{"abcd1234", "not in the RPM keyring"},
		},
		"untrusted key": {
			out:        "pkg.rpm:\n    Header V4 RSA/SHA256 Signature, key ID abcd1234: NOTTRUSTED",
			wantCauses: []string{"abcd1234", "not trusted"},
		},
		"bad signature": {
			out:        "pkg.rpm:\n    Header OpenPGP V4 RSA/SHA512 signature, key ID abcd1234: BAD",
			wantCauses: []string{"abcd1234", "does not match the package contents"},
		},
		"bad digest keeps the expected/actual detail": {
			out: "pkg.rpm:\n" +
				"    Header OpenPGP V4 RSA/SHA512 signature, key ID abcd1234: OK\n" +
				"    Header SHA256 digest: BAD (Expected 3797 != 78be)",
			wantCauses: []string{"Header SHA256 digest", "corrupt or truncated", "Expected 3797 != 78be"},
		},
		"unsigned package": {
			out: "pkg.rpm:\n" +
				"    Header SHA256 digest: OK\n" +
				"    Payload SHA256 digest: OK",
			wantCauses: []string{"no OpenPGP signature"},
		},
		"unrecognised result": {
			out:        "pkg.rpm:\n    Header SHA256 digest: WOBBLY",
			wantCauses: []string{`unrecognised result "WOBBLY"`},
		},
		"no checks at all": {
			// A file rpmkeys cannot read as a package yields no check lines;
			// CheckRPMSig turns that into its own problem, so the classifier
			// itself has nothing to report.
			out:         "pkg.rpm:",
			wantNoIssue: true,
		},
		// A path containing text that looks like a check result is echoed on the
		// first line only, and must not be parsed as one.
		"path that looks like a result": {
			out: "/tmp/digests OK/nokey: signature.rpm:\n" +
				"    Header OpenPGP V4 RSA/SHA512 signature, key ID abcd1234: OK\n" +
				"    Header SHA256 digest: OK",
			wantNoIssue: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			problems := rpmSigProblems(parseRPMSigChecks(tc.out))
			if tc.wantNoIssue {
				if len(problems) != 0 {
					t.Fatalf("rpmSigProblems: expected no problems, got %v", problemStrings(problems))
				}
				return
			}
			if len(problems) == 0 {
				t.Fatal("rpmSigProblems: expected a problem, got none")
			}
			if len(problems) != 1 {
				t.Errorf("rpmSigProblems: expected problems to be deduplicated, got %v", problemStrings(problems))
			}
			reported := strings.Join(problemStrings(problems), " ")
			for _, want := range tc.wantCauses {
				if !strings.Contains(reported, want) {
					t.Errorf("rpmSigProblems: %q does not mention %q", reported, want)
				}
			}
		})
	}
}

func TestCheckRPMSigs(t *testing.T) {
	env := newSigningEnv(t)

	signed := func(name string) string {
		rpm := env.buildTestRPM(t, name)
		if err := env.SignRPMFiles(env.keyID, []string{rpm}); err != nil {
			t.Fatalf("SignRPMFiles(%s): %v", name, err)
		}
		return rpm
	}

	t.Run("error for no files", func(t *testing.T) {
		if err := env.CheckRPMSigs(nil); err == nil {
			t.Error("CheckRPMSigs(nil): expected an error for an empty file list, got nil")
		}
	})

	t.Run("nil when every file is signed", func(t *testing.T) {
		rpms := []string{signed("multi1"), signed("multi2")}
		if err := env.CheckRPMSigs(rpms); err != nil {
			t.Errorf("CheckRPMSigs: unexpected error: %v", err)
		}
	})

	t.Run("aggregates one failure among good files", func(t *testing.T) {
		good := signed("mixedgood")
		bad := filepath.Join(t.TempDir(), "missing.rpm")
		err := env.CheckRPMSigs([]string{good, bad})
		if err == nil {
			t.Fatal("CheckRPMSigs: expected an error, got nil")
		}
		if n := strings.Count(err.Error(), "could not validate rpm file exists"); n != 1 {
			t.Errorf("expected exactly 1 signature failure, got %d in: %v", n, err)
		}
	})

	t.Run("aggregates failures across multiple bad files", func(t *testing.T) {
		dir := t.TempDir()
		err := env.CheckRPMSigs([]string{
			filepath.Join(dir, "missing1.rpm"),
			filepath.Join(dir, "missing2.rpm"),
		})
		if err == nil {
			t.Fatal("CheckRPMSigs: expected an error, got nil")
		}
		// errors.Join surfaces every underlying failure.
		if n := strings.Count(err.Error(), "could not validate rpm file exists"); n != 2 {
			t.Errorf("expected 2 aggregated failures, got %d in: %v", n, err)
		}
	})
}
