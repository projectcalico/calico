// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package ruleset

import (
	_ "embed"
	"fmt"
	"io/fs"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	//go:embed coreruleset/tigera.conf
	tigeraConf string
)

func GetOWASPCoreRuleSet() (*corev1.ConfigMap, error) {
	owaspCRS, err := fs.Sub(coreruleset.FS, "@owasp_crs")
	if err != nil {
		return nil, err
	}
	crsMap, err := asMap(owaspCRS)
	if err != nil {
		return nil, err
	}

	return asConfigMap(
		applicationlayer.DefaultCoreRuleset,
		common.OperatorNamespace(),
		crsMap,
	), nil
}

func GetWAFRulesetConfig() (*corev1.ConfigMap, error) {
	corazaConf, err := fs.ReadFile(coreruleset.FS, "@coraza.conf-recommended")
	if err != nil {
		return nil, err
	}

	crsSetup, err := fs.ReadFile(coreruleset.FS, "@crs-setup.conf.example")
	if err != nil {
		return nil, err
	}

	data := map[string]string{
		"tigera.conf":    tigeraConf,
		"coraza.conf":    string(corazaConf),
		"crs-setup.conf": string(crsSetup),
	}

	return asConfigMap(applicationlayer.WAFRulesetConfigMapName, common.OperatorNamespace(), data), nil
}

func ValidateWAFRulesetConfig(cm *corev1.ConfigMap) error {
	requiredFiles := []string{
		"tigera.conf",
		"coraza.conf",
		"crs-setup.conf",
	}

	for _, f := range requiredFiles {
		if _, ok := cm.Data[f]; !ok {
			return fmt.Errorf("file must be present with ruleset files: %s", f)
		}
	}

	return nil
}

func asConfigMap(name, namespace string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}
}

func asMap(fileSystem fs.FS) (map[string]string, error) {
	res := make(map[string]string)
	var walkFn fs.WalkDirFunc = func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return err
		}

		if b, err := fs.ReadFile(fileSystem, path); err != nil {
			return err
		} else {
			res[d.Name()] = string(b)
		}
		return nil
	}

	if err := fs.WalkDir(fileSystem, ".", walkFn); err != nil {
		return nil, fmt.Errorf("failed to walk core ruleset files (%w)", err)
	}

	return res, nil
}
