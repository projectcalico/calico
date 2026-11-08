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
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/command"
)

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
	keyring, err := NewRPMKeyring(&command.Recorder{}, filepath.Join(t.TempDir(), "rpmdb"))
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
// release agents fails the whole signing step with "unknown option".
func TestSignArgs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		help      string
		supported bool
	}{
		{name: "rpmsign accepts --rpmv4", help: "  --rpmv4   create rpm v4 signatures", supported: true},
		{name: "rpmsign rejects --rpmv4", help: "  --resign   sign packages", supported: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyring, err := NewRPMKeyring(helpRunner(tc.help, nil), filepath.Join(t.TempDir(), "rpmdb"))
			if err != nil {
				t.Fatalf("NewRPMKeyring: %v", err)
			}
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

func TestNewRPMKeyring(t *testing.T) {
	for _, tc := range []struct {
		name string
		help string
		err  error
		want bool
	}{
		{name: "rpmsign lists --rpmv4", help: "  --rpmv4   create rpm v4 signatures", want: true},
		{name: "rpmsign does not list it", help: "  --resign   sign packages", want: false},
		{name: "rpmsign fails", err: errors.New("not found"), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := helpRunner(tc.help, tc.err)
			keyring, err := NewRPMKeyring(r, filepath.Join(t.TempDir(), "rpmdb"))
			if err != nil {
				t.Fatalf("NewRPMKeyring: %v", err)
			}
			for range 2 {
				if got := keyring.supportsRPMV4(); got != tc.want {
					t.Errorf("supportsRPMV4() = %v, want %v", got, tc.want)
				}
			}
			if n := len(r.Calls()); n != 1 {
				t.Errorf("rpmsign --help ran %d times, want 1", n)
			}
		})
	}
}

func helpRunner(out string, err error) *command.Recorder {
	return &command.Recorder{Reply: func(c command.Call) (string, error) {
		if c.Name != "rpmsign" || !slices.Equal(c.Args, []string{"--help"}) {
			return "", fmt.Errorf("unexpected command %s %v", c.Name, c.Args)
		}
		return out, err
	}}
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

func TestCheckRPMSig(t *testing.T) {
	t.Run("a failure with passing checks reads the same for every file", func(t *testing.T) {
		r := &command.Recorder{Reply: func(c command.Call) (string, error) {
			file := c.Args[len(c.Args)-1]
			out := file + ":\n    Header V4 RSA/SHA256 Signature, key ID 2e3a1e31: OK\n"
			return out, &command.Error{Stdout: out, Stderr: "rpmkeys: fatal", Err: errors.New("exit status 1")}
		}}
		keyring, err := NewRPMKeyring(r, filepath.Join(t.TempDir(), "rpmdb"))
		if err != nil {
			t.Fatalf("NewRPMKeyring: %v", err)
		}
		dir := t.TempDir()
		var problems []string
		for _, name := range []string{"a.rpm", "b.rpm"} {
			file := filepath.Join(dir, name)
			if err := os.WriteFile(file, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			var sigErr *RPMSigCheckError
			if err := keyring.CheckRPMSig(file); !errors.As(err, &sigErr) {
				t.Fatalf("CheckRPMSig(%s) = %v, want an *RPMSigCheckError", name, err)
			}
			problems = append(problems, sigErr.Problems[0].String())
		}
		if problems[0] != problems[1] {
			t.Errorf("problems differ by file, so they cannot group:\n%s\n%s", problems[0], problems[1])
		}
	})
}
