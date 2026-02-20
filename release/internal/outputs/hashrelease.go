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

package outputs

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/slack"
)

var hashreleaseOutputFileName = "hashrelease.yaml"

// PublishedHashrelease represents the output of a hashrelease publication.
type PublishedHashrelease struct {
	Hashrelease    *hashreleaseserver.Hashrelease `yaml:"-,inline"`
	HashreleaseURL string                         `yaml:"url"`
	SlackResponse  *slack.MessageResponse         `yaml:"slack,omitempty"`
}

func (h *PublishedHashrelease) Write(outputDir string) (string, error) {
	h.HashreleaseURL = h.Hashrelease.URL()
	fqPath := filepath.Join(outputDir, hashreleaseOutputFileName)
	f, err := os.Create(fqPath)
	if err != nil {
		return "", fmt.Errorf("creating hashrelease output file: %w", err)
	}
	defer func() { _ = f.Close() }()

	encoder := yaml.NewEncoder(f)
	encoder.SetIndent(2)
	defer func() { _ = encoder.Close() }()

	if err := encoder.Encode(h); err != nil {
		return "", fmt.Errorf("writing hashrelease output to %s: %w", fqPath, err)
	}
	return fqPath, nil
}
