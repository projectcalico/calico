// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package localregistry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
)

// testResource is a minimal authn.Resource (registry host) for keychain lookups.
type testResource string

func (r testResource) String() string      { return string(r) }
func (r testResource) RegistryStr() string { return string(r) }

func TestLoadExtraKeychain(t *testing.T) {
	// Empty path and a missing file both yield nil, so Start can wire the extra
	// config in unconditionally and fall back to the host keychain alone.
	if loadExtraKeychain("") != nil {
		t.Error("empty path should yield nil keychain")
	}
	if loadExtraKeychain(filepath.Join(t.TempDir(), "absent.json")) != nil {
		t.Error("missing file should yield nil keychain")
	}

	// A config with no auths is treated as nothing to add.
	empty := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(empty, []byte(`{"auths":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if loadExtraKeychain(empty) != nil {
		t.Error("config with no auths should yield nil keychain")
	}

	// Entries with no credential material, or a key that normalises to an empty
	// host, are skipped — so they can't shadow the host keychain with an empty
	// AuthConfig. With nothing usable left, the result is nil.
	junk := filepath.Join(t.TempDir(), "junk.json")
	if err := os.WriteFile(junk, []byte(`{"auths":{"quay.io":{},"https://":{"auth":"dXNlcjpwYXNz"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if loadExtraKeychain(junk) != nil {
		t.Error("config with only empty-cred / empty-host entries should yield nil keychain")
	}

	// A real cred keyed by a legacy URL, to also exercise registryHost.
	cfg := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfg, []byte(`{"auths":{"https://quay.io/v1/":{"auth":"dXNlcjpwYXNz"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	kc := loadExtraKeychain(cfg)
	if kc == nil {
		t.Fatal("expected a keychain for a config with auths")
	}

	// quay.io resolves to the configured credential...
	auth, err := kc.Resolve(testResource("quay.io"))
	if err != nil {
		t.Fatalf("resolve quay.io: %v", err)
	}
	ac, err := auth.Authorization()
	if err != nil {
		t.Fatalf("authorization: %v", err)
	}
	if ac.Auth != "dXNlcjpwYXNz" {
		t.Errorf("quay.io auth = %q, want the config value", ac.Auth)
	}

	// ...and an unlisted registry falls back to anonymous (so the host keychain,
	// layered first via NewMultiKeychain, keeps handling e.g. gcr.io).
	other, err := kc.Resolve(testResource("gcr.io"))
	if err != nil {
		t.Fatalf("resolve gcr.io: %v", err)
	}
	if other != authn.Anonymous {
		t.Errorf("unlisted registry should resolve anonymous, got %#v", other)
	}
}

func TestRegistryHost(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"quay.io", "quay.io"},
		{"https://quay.io/v1/", "quay.io"},
		{"http://index.docker.io/v1/", "index.docker.io"},
		{"gcr.io", "gcr.io"},
	} {
		if got := registryHost(tc.in); got != tc.want {
			t.Errorf("registryHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
