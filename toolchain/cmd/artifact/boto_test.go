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

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIniValue(t *testing.T) {
	for _, tc := range []struct {
		name, config, want string
	}{
		{name: "handler config", config: "[Credentials]\ngs_service_key_file = /etc/argoci/artifacts-sa/key.json\n", want: "/etc/argoci/artifacts-sa/key.json"},
		{name: "colon separator", config: "[Credentials]\ngs_service_key_file: /k.json\n", want: "/k.json"},
		{name: "no spaces", config: "[Credentials]\ngs_service_key_file=/k.json", want: "/k.json"},
		{name: "surrounding whitespace", config: "  [Credentials]  \r\n\t gs_service_key_file \t=\t /k.json \r\n", want: "/k.json"},
		{name: "option name ignores case", config: "[Credentials]\nGS_Service_Key_File = /k.json\n", want: "/k.json"},
		{name: "section name keeps case", config: "[credentials]\ngs_service_key_file = /k.json\n", want: ""},
		{name: "other section", config: "[Boto]\ngs_service_key_file = /k.json\n", want: ""},
		{name: "section switches", config: "[Credentials]\ngs_service_key_file = /a\n[GSUtil]\ngs_service_key_file = /b\n", want: "/a"},
		{name: "later sections", config: "[GSUtil]\nparallel_thread_count = 4\n[Credentials]\ngs_service_key_file = /k.json\n", want: "/k.json"},
		{name: "comments", config: "# gs_service_key_file = /no\n[Credentials]\n; gs_service_key_file = /no\n  # indented comment\ngs_service_key_file = /k.json\n", want: "/k.json"},
		{name: "inline comment is part of the value", config: "[Credentials]\ngs_service_key_file = /k.json # key\n", want: "/k.json # key"},
		{name: "first separator wins", config: "[Credentials]\ngs_service_key_file = C:/k.json\n", want: "C:/k.json"},
		{name: "continuation line", config: "[Credentials]\ngs_service_key_file = /a\n  /b\nother = x\n", want: "/a\n/b"},
		{name: "missing option", config: "[Credentials]\ngs_oauth2_refresh_token = x\n", want: ""},
		{name: "unsupported spelling", config: "[Credentials]\ngs_json_keyfile_path = /k.json\n", want: ""},
		{name: "empty", config: "", want: ""},
	} {
		got, err := iniValue(strings.NewReader(tc.config), "Credentials", "gs_service_key_file")
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
}

func TestIniValueMalformed(t *testing.T) {
	for _, config := range []string{
		"[Credentials]\njust words\n",
		"gs_service_key_file = /k.json\n",
	} {
		if _, err := iniValue(strings.NewReader(config), "Credentials", "gs_service_key_file"); err == nil {
			t.Errorf("%q: no error", config)
		}
	}
}

func TestBotoServiceKeyFile(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "boto.cfg")
	must(t, os.WriteFile(cfg, []byte("[Credentials]\ngs_service_key_file = /k.json\n"), 0o600))

	if got, err := botoServiceKeyFile(cfg); err != nil || got != "/k.json" {
		t.Errorf("got %q, %v", got, err)
	}
	for _, path := range []string{"", filepath.Join(dir, "missing.cfg"), dir} {
		if got, err := botoServiceKeyFile(path); err != nil || got != "" {
			t.Errorf("%q: got %q, %v; want fall through", path, got, err)
		}
	}

	t.Setenv("HOME", dir)
	if got, err := botoServiceKeyFile("~/boto.cfg"); err != nil || got != "/k.json" {
		t.Errorf("~ not expanded: got %q, %v", got, err)
	}
}

func TestCredentialsFromBotoKey(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.json")
	cfg := filepath.Join(dir, "boto.cfg")
	must(t, os.WriteFile(cfg, []byte("[Credentials]\ngs_service_key_file = "+key+"\n"), 0o600))
	env := func(k string) string {
		if k == "BOTO_CONFIG" {
			return cfg
		}
		return ""
	}

	// gsutil fails rather than falling back when configured credentials
	// cannot be loaded.
	if _, err := credentialOptions(context.Background(), env); err == nil || !strings.Contains(err.Error(), "gs_service_key_file") {
		t.Fatalf("unreadable key: err = %v", err)
	}

	must(t, os.WriteFile(key, []byte(`{"type":"service_account"}`), 0o600))
	opts, err := credentialOptions(context.Background(), env)
	if err != nil || len(opts) != 1 {
		t.Fatalf("got %d options, %v", len(opts), err)
	}
}
