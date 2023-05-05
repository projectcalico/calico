// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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
package testutils

import (
	"context"
	"time"

	. "github.com/onsi/gomega"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DeleteNamespace deletes the namespace and waits for it to complete.
func DeleteNamespace(client *kubernetes.Clientset, name string) {
	var zero int64
	err := client.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{
		GracePeriodSeconds: &zero,
	})
	if err != nil && !kerrors.IsNotFound(err) {
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	}
	EventuallyWithOffset(1, func() bool {
		_, err = client.CoreV1().Namespaces().Get(context.Background(), name, metav1.GetOptions{})
		return kerrors.IsNotFound(err)
	}, 30*time.Second).Should(BeTrue())
}
