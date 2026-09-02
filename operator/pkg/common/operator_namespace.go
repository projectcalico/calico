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

	"github.com/cloudflare/cfssl/log"
	"k8s.io/apimachinery/pkg/types"
)

var namespace = ""

func init() {
	v, ok := os.LookupEnv("OPERATOR_NAMESPACE")
	if ok {
		namespace = v
		return
	}
	body, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Errorf("Failed to read namespace file: %v", err)
	} else {
		namespace = string(body)
		return
	}

	namespace = "tigera-operator"
}

// OperatorNamespace returns the namespace the operator is running in.
// The value returned is based on the following priority (these are evaluated at startup):
//
//	If the OPERATOR_NAMESPACE environment variable is non-empty then that is return.
//	If the file /var/run/secrets/kubernetes.io/serviceaccount/namespace is non-empty
//	then the contents is returned.
//	The default "tigera-operator" is returned.
func OperatorNamespace() string {
	return namespace
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
