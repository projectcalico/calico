// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package logcollector

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

func (c *fluentBitComponent) fluentBitConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: c.fluentBitConfConfigMapName(), Namespace: LogCollectorNamespace},
		Data:       map[string]string{"fluent-bit.yaml": c.renderFluentBitConf()},
	}
}

func (c *fluentBitComponent) logInputs() []logInput {
	if c.osType == rmeta.OSTypeWindows {
		return windowsLogInputs
	}
	return linuxLogInputs
}

// logDirsCSV lists the tailed log directories (comma-separated) for the
// pos-migrator init container to pre-create: glob tail inputs (compliance) log
// a scan error on every refresh while their parent directory is missing, e.g.
// on clusters where the producing feature isn't enabled yet. Deriving the list
// from logInputs keeps a single source of truth for the tailed paths.
func (c *fluentBitComponent) logDirsCSV() string {
	var dirs []string
	seen := map[string]bool{}
	for _, in := range c.logInputs() {
		dir := c.path(in.path[:strings.LastIndex(in.path, "/")])
		if !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	return strings.Join(dirs, ",")
}

func (c *fluentBitComponent) trustedBundlePath() string {
	if c.osType == rmeta.OSTypeWindows {
		return certificatemanagement.TrustedCertBundleMountPathWindows
	}
	return c.cfg.TrustedBundle.MountPath()
}

func (c *fluentBitComponent) keyPath() string {
	if c.osType == rmeta.OSTypeWindows {
		return fmt.Sprintf("c:/%s/%s", c.cfg.FluentBitKeyPair.GetName(), corev1.TLSPrivateKeyKey)
	}
	return c.cfg.FluentBitKeyPair.VolumeMountKeyFilePath()
}

func (c *fluentBitComponent) certPath() string {
	if c.osType == rmeta.OSTypeWindows {
		return fmt.Sprintf("c:/%s/%s", c.cfg.FluentBitKeyPair.GetName(), corev1.TLSCertKey)
	}
	return c.cfg.FluentBitKeyPair.VolumeMountCertificateFilePath()
}
