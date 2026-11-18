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

package render_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/k8sapi"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/render"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
)

var _ = Describe("Windows certificate management", func() {
	It("provisions the node certs into the volume felix reads them from", func() {
		e := newOverrideRenderEnv()
		comp := render.Windows(&render.WindowsConfiguration{
			K8sServiceEp:  k8sapi.ServiceEndpoint{Host: "1.2.3.4", Port: "6443"},
			K8sDNSServers: []string{"10.96.0.10"},
			Installation:  e.installation,
			ClusterDomain: dns.DefaultClusterDomain,
			TLS:           e.tls,
			VXLANVNI:      4096,
		})
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		objs, _ := comp.Objects()
		ds := named[*appsv1.DaemonSet](common.WindowsDaemonSetName)(objs).(*appsv1.DaemonSet)
		spec := ds.Spec.Template.Spec

		provisioner := rtest.GetContainer(spec.InitContainers, render.NodeTLSSecretName+"-key-cert-provisioner")
		Expect(provisioner).NotTo(BeNil())
		var certPath string
		for _, env := range provisioner.Env {
			if env.Name == "CERTIFICATE_PATH" {
				certPath = env.Value
			}
		}
		Expect(provisioner.VolumeMounts).To(ContainElement(corev1.VolumeMount{
			Name:      render.NodeTLSSecretName,
			MountPath: strings.TrimSuffix(certPath, "/"),
		}))

		felix := rtest.GetContainer(spec.Containers, "felix")
		Expect(felix).NotTo(BeNil())
		Expect(felix.VolumeMounts).To(ContainElement(HaveField("Name", render.NodeTLSSecretName)))
	})
})
