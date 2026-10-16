// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalSecretWritesModeAndContent(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "nested", "dir", "secret")
	t.Setenv("TEST_SECRET_VAR", "s3cr3t")

	found, err := LocalSecret("TEST_SECRET_VAR", dest)
	if err != nil || !found {
		t.Fatalf("LocalSecret: found=%v err=%v", found, err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "s3cr3t" {
		t.Errorf("content = %q, want %q", got, "s3cr3t")
	}
	// Readable by anyone but the owner would defeat the point.
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %#o, want 0600", perm)
	}
}

// An unset var is a no-op, not an error: the caller decides whether that is fatal,
// which is what MustLocalSecret is for.
func TestLocalSecretMissingVarIsNoOp(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "secret")
	found, err := LocalSecret("TEST_SECRET_VAR_DEFINITELY_UNSET", dest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("found = true for an unset env var")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Error("a file was created for an unset env var")
	}
}

func TestLocalSecretEmptyValueStillWrites(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "secret")
	t.Setenv("TEST_SECRET_EMPTY", "")
	found, err := LocalSecret("TEST_SECRET_EMPTY", dest)
	if err != nil || !found {
		t.Fatalf("a set-but-empty var should still be written: found=%v err=%v", found, err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestMustLocalSecretErrorsWhenUnset(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "secret")
	if err := MustLocalSecret("TEST_SECRET_VAR_DEFINITELY_UNSET", dest); err == nil {
		t.Fatal("want an error for a required-but-unset secret")
	}
}

// The key must land on a private, per-run path: O_EXCL at 0600 with a random
// name, so it cannot follow a symlink or collide with a concurrent run.
func TestSetupComputeADCUsesAPrivateUniqueFile(t *testing.T) {
	t.Setenv("COMPUTE_SA_KEY", "")
	t.Setenv("COMPUTE_SA_ENV", "TEST_SA_JSON")
	t.Setenv("TEST_SA_JSON", `{"type":"service_account"}`)

	var paths []string
	for range 2 {
		if err := SetupComputeADC(); err != nil {
			t.Fatalf("SetupComputeADC: %v", err)
		}
		p := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
		paths = append(paths, p)
		t.Cleanup(func() { os.Remove(p) })

		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `{"type":"service_account"}` {
			t.Errorf("content = %q", got)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %#o, want 0600", perm)
		}
	}
	// Two runs in one namespace must not fight over the same file.
	if paths[0] == paths[1] {
		t.Errorf("both runs used the same path %q", paths[0])
	}
}

func TestSetupComputeADCErrorsWhenTheEnvVarIsMissing(t *testing.T) {
	t.Setenv("COMPUTE_SA_KEY", "")
	t.Setenv("COMPUTE_SA_ENV", "TEST_SA_DEFINITELY_UNSET")
	if err := SetupComputeADC(); err == nil {
		t.Fatal("want an error when the named env var is unset")
	}
}
