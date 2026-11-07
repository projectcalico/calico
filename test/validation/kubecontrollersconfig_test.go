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

package validation_test

import (
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// kube-controllers parses the level with logrus, which knows Trace but not None.
func TestKubeControllersConfiguration_LogSeverityScreen(t *testing.T) {
	tests := []struct {
		level   string
		wantErr string
	}{
		{level: "Trace"},
		{level: "Warning"},
		{level: "None", wantErr: `Unsupported value: "None"`},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			obj := &v3.KubeControllersConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("kcc-log")},
				Spec:       v3.KubeControllersConfigurationSpec{LogSeverityScreen: tt.level},
			}
			if tt.wantErr != "" {
				expectCreateFails(t, obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, obj)
			}
		})
	}
}
