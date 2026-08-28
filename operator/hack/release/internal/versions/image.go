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

package versions

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/tigera/operator/hack/release/internal/command"
)

// sedReplacer escapes a string for use as the replacement in `sed s|...|REPL|` (with `|` as delimiter).
// It escapes the backreference/ampersand (&), backslash (\\), and the chosen delimiter (|).
var sedReplacer = strings.NewReplacer(`\`, `\\`, `&`, `\&`, `|`, `\|`)

// Component image config key constants used as keys in ModifyComponentImageConfig.
const (
	CalicoRegistryConfigKey      = "CalicoRegistry"
	CalicoImagePathConfigKey     = "CalicoImagePath"
	EnterpriseRegistryConfigKey  = "TigeraRegistry"
	EnterpriseImagePathConfigKey = "TigeraImagePath"
	OperatorRegistryConfigKey    = "OperatorRegistry"
	OperatorImagePathConfigKey   = "OperatorImagePath"
)

// ComponentImageConfigRelPath is the repo-relative path to the component image config file.
var ComponentImageConfigRelPath = "pkg/components/images.go"

// componentImageConfigMap maps config keys to human-readable descriptions.
var componentImageConfigMap = map[string]string{
	CalicoRegistryConfigKey:      "Calico Registry",
	CalicoImagePathConfigKey:     "Calico Image Path",
	EnterpriseRegistryConfigKey:  "Enterprise Registry",
	EnterpriseImagePathConfigKey: "Enterprise Image Path",
	OperatorRegistryConfigKey:    "Operator Registry",
	OperatorImagePathConfigKey:   "Operator Image Path",
}

// ModifyComponentImageConfig modifies variables in the specified component image config file.
func ModifyComponentImageConfig(repoRootDir, imageConfigRelPath, configKey, newValue string) error {
	// Check the configKey is valid
	desc, ok := componentImageConfigMap[configKey]
	if !ok {
		return fmt.Errorf("invalid component image config key: %s", configKey)
	}

	logrus.WithField("repoDir", repoRootDir).WithField(configKey, newValue).Infof("Updating %s in %s", desc, imageConfigRelPath)

	if out, err := command.RunInDir(repoRootDir, "sed", []string{"-i", fmt.Sprintf(`s|%s.*=.*".*"|%s = "%s"|`, regexp.QuoteMeta(configKey), configKey, sedReplacer.Replace(newValue)), imageConfigRelPath}, nil); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to update %s in %s: %w", desc, imageConfigRelPath, err)
	}
	return nil
}
