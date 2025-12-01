// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package remotecluster

import (
	"strings"

	"github.com/onsi/gomega"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/config"
)

const RemoteClusterNamespacePrefix = "rmt-"

func IsRemoteClusterFramework(f *framework.Framework) bool {
	return f != nil && f.Namespace != nil && strings.HasPrefix(f.Namespace.Name, RemoteClusterNamespacePrefix)
}

// RemoteFrameworkAwareExec is used to execute commands in a context that forces the executed function to utilize the
// remote kubeconfig. While the framework.Framework returned by NewDefaultFrameworkForRemoteCluster automatically
// ensures that actions are executed against the remote cluster in most cases, some cases cannot be handled purely by
// the modified framework.Framework object. These cases typically occur when commands are executed against a cluster
// without the use of the f.ClientSet, like when running kubectl commands or building a k8s calico client. Usages of
// RemoteFrameworkAwareExec should be embedded into existing utilities so that developers do not need to think about
// which functions do not use f.ClientSet when writing tests for remote clusters.
func RemoteFrameworkAwareExec(f *framework.Framework, fn func()) {
	if IsRemoteClusterFramework(f) && config.RemoteClusterKubeconfig() != "" {
		// Capture the original kubeconfig path and host, defer their reset.
		originalKubeconfig := framework.TestContext.KubeConfig
		originalHost := framework.TestContext.Host
		defer func() {
			framework.TestContext.KubeConfig = originalKubeconfig
			framework.TestContext.Host = originalHost
		}()

		// Resolve the new kubeconfig path.
		newKubeconfigPath := config.RemoteClusterKubeconfig()

		// Resolve the new host.
		newKubeconfig, err := clientcmd.LoadFromFile(newKubeconfigPath)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var newKubeconfigContext string
		if strings.Contains(newKubeconfig.CurrentContext, "@") {
			// Some generated kubeconfigs will include a username in the context string.
			newKubeconfigContext = strings.Split(newKubeconfig.CurrentContext, "@")[1]
		} else {
			newKubeconfigContext = newKubeconfig.CurrentContext
		}
		cluster := newKubeconfig.Clusters[newKubeconfigContext]
		gomega.Expect(cluster).NotTo(gomega.BeNil())
		newHost := cluster.Server

		// Set the new kubeconfig path and host.
		framework.TestContext.KubeConfig = newKubeconfigPath
		framework.TestContext.Host = newHost
	}

	// Execute the passed function.
	fn()
}
