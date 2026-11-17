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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGoldenConfigsParse checks every golden config with the BIRD binaries that calico/node
// ships. BIRD refuses a whole config over one bad line, and the golden comparison alone cannot
// tell that a rendered config is one BIRD accepts.
func TestGoldenConfigsParse(t *testing.T) {
	binaries := map[string]string{
		"bird.cfg":  birdBinary(t, "bird"),
		"bird6.cfg": birdBinary(t, "bird6"),
	}

	parsed := 0
	err := filepath.WalkDir("compiled_templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		binary, ok := binaries[d.Name()]
		if !ok {
			return nil
		}
		out, err := birdParse(binary, path)
		require.NoError(t, err, "BIRD rejected %s: %s", path, out)
		parsed++
		return nil
	})
	require.NoError(t, err)
	require.NotZero(t, parsed, "no golden configs found")
}

// TestInvalidConfigRejected guards TestGoldenConfigsParse against a parse check that accepts
// anything.
func TestInvalidConfigRejected(t *testing.T) {
	config := filepath.Join(t.TempDir(), "bird.cfg")
	require.NoError(t, os.WriteFile(config, []byte("protocol nonsense {\n}\n"), 0o644))

	for _, name := range []string{"bird", "bird6"} {
		out, err := birdParse(birdBinary(t, name), config)
		require.Error(t, err, "%s accepted an invalid config: %s", name, out)
	}
}

func birdBinary(t *testing.T, name string) string {
	path, err := filepath.Abs(filepath.Join("..", "bin", name))
	require.NoError(t, err)
	_, err = os.Stat(path)
	require.NoError(t, err, "missing %s: run `make -C confd bin/bird bin/bird6`", path)
	return path
}

// birdParse runs BIRD's parse-only check from the config's directory, because the config's
// includes are relative.
func birdParse(binary, config string) ([]byte, error) {
	cmd := exec.Command(binary, "-p", "-c", filepath.Base(config))
	cmd.Dir = filepath.Dir(config)
	return cmd.CombinedOutput()
}
