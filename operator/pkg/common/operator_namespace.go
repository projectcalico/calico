// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package common

import (
	"os"
	"sync"

	"github.com/cloudflare/cfssl/log"
	"k8s.io/apimachinery/pkg/types"
)

var (
	namespace = ""

	// namespaceOnce ensures that namespace is initialized only once.
	namespaceOnce sync.Once
)

// OperatorNamespace returns the namespace the operator is running in: OPERATOR_NAMESPACE if
// set, else the service account's namespace file, else the default "tigera-operator".
// Resolved on the first call.
func OperatorNamespace() string {
	namespaceOnce.Do(func() {
		namespace = getNamespace()
	})
	return namespace
}

func getNamespace() string {
	if v, ok := os.LookupEnv("OPERATOR_NAMESPACE"); ok {
		return v
	}

	body, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		// Absent outside a cluster, where the default is the right answer anyway.
		log.Infof("Failed to read namespace file, using default: %v", err)
		return "tigera-operator"
	}
	return string(body)
}

// OperatorName returns the name of the operator deployment.
func OperatorName() string {
	name := "tigera-operator"
	if v, ok := os.LookupEnv("OPERATOR_NAME"); ok && v != "" {
		name = v
	}
	return name
}

func OperatorKey() types.NamespacedName {
	return types.NamespacedName{
		Name:      OperatorName(),
		Namespace: OperatorNamespace(),
	}
}
