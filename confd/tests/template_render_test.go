// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/confd/pkg/backends/types"
	tmpl "github.com/projectcalico/calico/confd/pkg/resource/template"
)

// mockStoreClient implements backends.StoreClient for template rendering tests.
type mockStoreClient struct {
	configV4 *types.BirdBGPConfig
	configV6 *types.BirdBGPConfig
}

func (m *mockStoreClient) SetPrefixes(keys []string) error { return nil }
func (m *mockStoreClient) GetValues(keys []string) (map[string]string, error) {
	return map[string]string{}, nil
}
func (m *mockStoreClient) WatchPrefix(prefix string, keys []string, waitIndex uint64, stopChan chan bool) (string, error) {
	return "", nil
}
func (m *mockStoreClient) GetCurrentRevision() uint64 { return 1 }
func (m *mockStoreClient) GetBirdBGPConfig(ipVersion int) (*types.BirdBGPConfig, error) {
	if ipVersion == 6 {
		return m.configV6, nil
	}
	return m.configV4, nil
}

// templateTestCase defines a template rendering test scenario.
type templateTestCase struct {
	name      string
	configV4  *types.BirdBGPConfig
	configV6  *types.BirdBGPConfig
	kvData    map[string]string
	goldenDir string
}

var templateDir = filepath.Join("..", "etc", "calico", "confd", "templates")

// templateFiles maps template filenames to their golden output filenames.
var templateFiles = []struct {
	template string
	golden   string
}{
	{"bird.cfg.template", "bird.cfg"},
	{"bird6.cfg.template", "bird6.cfg"},
	{"bird_ipam.cfg.template", "bird_ipam.cfg"},
	{"bird6_ipam.cfg.template", "bird6_ipam.cfg"},
	{"bird_aggr.cfg.template", "bird_aggr.cfg"},
	{"bird6_aggr.cfg.template", "bird6_aggr.cfg"},
}

func TestTemplateRendering(t *testing.T) {
	tests := []templateTestCase{
		meshBGPExport(),
		meshIPIPAlways(),
		meshIPIPCrossSubnet(),
		meshIPIPOff(),
		meshVXLANAlways(),
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &mockStoreClient{
				configV4: tc.configV4,
				configV6: tc.configV6,
			}

			for _, tf := range templateFiles {
				t.Run(tf.golden, func(t *testing.T) {
					templatePath := filepath.Join(templateDir, tf.template)
					got, err := tmpl.RenderTemplate(templatePath, client, tc.kvData)
					require.NoError(t, err, "rendering template %s", tf.template)

					want := readGolden(t, tc.goldenDir, tf.golden)
					if normalizeBlankLines(got) != normalizeBlankLines(want) {
						t.Errorf("template output mismatch for %s\n\n--- want ---\n%s\n\n--- got ---\n%s", tf.golden, want, got)
					}
				})
			}
		})
	}
}

func readGolden(t *testing.T, goldenDir, filename string) string {
	t.Helper()
	path := filepath.Join("compiled_templates", goldenDir, filename)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "reading golden file %s", path)
	return string(data)
}

func normalizeBlankLines(s string) string {
	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}
