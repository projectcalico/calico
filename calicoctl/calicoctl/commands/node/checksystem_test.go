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

package node

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLsmodHasModule(t *testing.T) {
	lsmod := `Module                  Size  Used by
xt_set                 16384  4
ip_set                 61440  3
vfio_pci               65536  0
`

	cases := []struct {
		name string
		want bool
	}{
		{"xt_set", true},
		{"ip_set", true},
		{"vfio_pci", true},
		{"vfio-pci", true}, // hyphenated alias
		{"ipt_set", false},
		{"xt_set_extra", false},
	}
	for _, tc := range cases {
		if got := lsmodHasModule(lsmod, tc.name); got != tc.want {
			t.Errorf("lsmodHasModule(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCheckModuleFileCompressedAndBuiltin(t *testing.T) {
	dir := t.TempDir()
	dep := filepath.Join(dir, "modules.dep")
	builtin := filepath.Join(dir, "modules.builtin")

	if err := os.WriteFile(dep, []byte(
		"kernel/net/netfilter/xt_set.ko.xz: kernel/net/netfilter/ip_set.ko.xz\n"+
			"kernel/drivers/vfio/pci/vfio-pci.ko.zst:\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(builtin, []byte(
		"kernel/net/ipv4/netfilter/ip_tables.ko\n"+
			"kernel/net/netfilter/xt_conntrack.ko\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := checkModuleFile(dep, "xt_set"); err != nil {
		t.Errorf("expected xt_set in modules.dep: %v", err)
	}
	if err := checkModuleFile(dep, "vfio-pci"); err != nil {
		t.Errorf("expected vfio-pci in modules.dep: %v", err)
	}
	if err := checkModuleFile(dep, "ipt_set"); err == nil {
		t.Error("did not expect ipt_set in modules.dep")
	}
	if err := checkModuleFile(builtin, "ip_tables"); err != nil {
		t.Errorf("expected ip_tables in modules.builtin: %v", err)
	}
	if err := checkModuleFile(builtin, "xt_conntrack"); err != nil {
		t.Errorf("expected xt_conntrack in modules.builtin: %v", err)
	}
}

func TestModuleAvailableXtSetViaLegacyIptSet(t *testing.T) {
	dir := t.TempDir()
	dep := filepath.Join(dir, "modules.dep")
	builtin := filepath.Join(dir, "modules.builtin")
	boot := filepath.Join(dir, "config")

	// Old distro only ships ipt_set; xt_set entry should still pass via Alternatives.
	if err := os.WriteFile(dep, []byte("kernel/net/netfilter/ipt_set.ko:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(builtin, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(boot, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	mod := moduleCheck{
		Name:          "xt_set",
		ConfigOptions: []string{"CONFIG_NETFILTER_XT_SET"},
		Alternatives:  []string{"ipt_set"},
	}
	if !moduleAvailable(mod, dep, builtin, boot, "") {
		t.Fatal("xt_set should be satisfied by ipt_set alternative")
	}
}

func TestModuleAvailableOptionalMissing(t *testing.T) {
	dir := t.TempDir()
	dep := filepath.Join(dir, "modules.dep")
	builtin := filepath.Join(dir, "modules.builtin")
	boot := filepath.Join(dir, "config")
	for _, p := range []string{dep, builtin, boot} {
		if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mod := moduleCheck{
		Name:          "xt_u32",
		ConfigOptions: []string{"CONFIG_NETFILTER_XT_MATCH_U32"},
		Optional:      true,
	}
	if moduleAvailable(mod, dep, builtin, boot, "") {
		t.Fatal("xt_u32 should be missing")
	}
}

func TestCheckModuleConfigYAndM(t *testing.T) {
	dir := t.TempDir()
	boot := filepath.Join(dir, "config")
	if err := os.WriteFile(boot, []byte("CONFIG_IP_SET=y\nCONFIG_NETFILTER_XT_SET=m\n# CONFIG_FOO is not set\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkModule(boot, "CONFIG_IP_SET", "^%s=[ym]"); err != nil {
		t.Errorf("CONFIG_IP_SET=y should match: %v", err)
	}
	if err := checkModule(boot, "CONFIG_NETFILTER_XT_SET", "^%s=[ym]"); err != nil {
		t.Errorf("CONFIG_NETFILTER_XT_SET=m should match: %v", err)
	}
	if err := checkModule(boot, "CONFIG_FOO", "^%s=[ym]"); err == nil {
		t.Error("unset CONFIG_FOO should not match")
	}
}

func TestRequiredModulesHasNoDuplicateFeatureRows(t *testing.T) {
	// ipt_set / ipt_rpfilter / xt_icmp must not appear as primary Name rows.
	banned := map[string]bool{"ipt_set": true, "ipt_rpfilter": true, "xt_icmp": true, "xt_icmp6": true}
	for _, mod := range requiredModules {
		if banned[mod.Name] {
			t.Errorf("unexpected primary module row %q", mod.Name)
		}
	}
}
