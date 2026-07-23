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

package names

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

const (
	serviceAccountNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	defaultNamespace            = "calico-system"
)

// OwnNamespace returns the namespace this process is running in by reading
// the downward API service account namespace file. If the file can't be read
// (e.g., during tests or outside a pod), it returns "calico-system".
func OwnNamespace() string {
	data, err := os.ReadFile(winutils.GetHostPath(serviceAccountNamespaceFile))
	if err != nil {
		logrus.WithError(err).Debug("Failed to read service account namespace file, defaulting to calico-system")
		return defaultNamespace
	}
	ns := strings.TrimSpace(string(data))
	if ns == "" {
		return defaultNamespace
	}
	return ns
}
