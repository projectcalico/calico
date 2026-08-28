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

package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	//nolint:staticcheck // Ignore ST1001 error strings should not be capitalized
	. "github.com/onsi/gomega"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func ExpectK8sServiceEpEnvVars(podSpec corev1.PodSpec, host, port string) {
	for _, c := range podSpec.Containers {
		ExpectWithOffset(1, c.Env).To(ContainElements(
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: host},
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: port},
		), fmt.Sprintf("Container %s did not have KUBERNETES_SERVICE_... env vars", c.Name))
	}
	for _, c := range podSpec.InitContainers {
		ExpectWithOffset(1, c.Env).To(ContainElements(
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: host},
			corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: port},
		), fmt.Sprintf("Init container %s did not have KUBERNETES_SERVICE_... env vars", c.Name))
	}
}

func ExpectNoK8sServiceEpEnvVars(podSpec corev1.PodSpec) {
	for _, c := range podSpec.Containers {
		for _, ev := range c.Env {
			ExpectWithOffset(1, ev.Name).NotTo(Equal("KUBERNETES_SERVICE_HOST"))
			ExpectWithOffset(1, ev.Name).NotTo(Equal("KUBERNETES_SERVICE_PORT"))
		}
	}
	for _, c := range podSpec.InitContainers {
		for _, ev := range c.Env {
			ExpectWithOffset(1, ev.Name).NotTo(Equal("KUBERNETES_SERVICE_HOST"))
			ExpectWithOffset(1, ev.Name).NotTo(Equal("KUBERNETES_SERVICE_PORT"))
		}
	}
}

func ExpectResourceInList(objs []client.Object, name, ns, group, version, kind string) {
	type expectedResource struct {
		Name      string
		Namespace string
		GVK       schema.GroupVersionKind
	}

	o := expectedResource{
		Name:      name,
		Namespace: ns,
		GVK:       schema.GroupVersionKind{Group: group, Version: version, Kind: kind},
	}

	elems := []expectedResource{}
	for _, obj := range objs {
		elems = append(elems, expectedResource{
			Name:      obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName(),
			Namespace: obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
			GVK:       obj.GetObjectKind().GroupVersionKind(),
		})
	}
	Expect(elems).To(ContainElement(o))
}

// ExpectResources checks that the given list of resources contains the expected resources, and that
// the given resource list does not contain any unexpected resources.
func ExpectResources(resources []client.Object, expected []client.Object) {
	// First, check that each actual resource is in the expected list.
	for _, resource := range resources {
		ExpectWithOffset(1, ExpectResource(resource, expected)).NotTo(HaveOccurred(), "Unexpected resouce was rendered")
	}

	// Then, check that each expected resource is in the actual list.
	for _, resource := range expected {
		ExpectWithOffset(1, ExpectResource(resource, resources)).NotTo(HaveOccurred(), "Expected resource was not rendered")
	}
}

// ExpectResource checks that the given list of resources contains a resource with the given name and
// namespace, and that the resource has the given GroupVersionKind.
func ExpectResource(expected client.Object, resources []client.Object) error {
	name := expected.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
	ns := expected.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()

	for _, resource := range resources {
		if reflect.TypeOf(resource) == reflect.TypeOf(expected) {
			if resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName() == name &&
				resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace() == ns {
				// Same type, name, and namespace. Consider it a match.
				return nil
			}
		}
	}
	return notFoundError(name, ns, expected, resources)
}

func notFoundError(name, ns string, o client.Object, resources []client.Object) error {
	if ns == "" {
		return fmt.Errorf("%T %s not found in:\n\n%s", o, name, itemList(resources))
	}
	return fmt.Errorf("%T %s/%s not found in:\n\n%s", o, ns, name, itemList(resources))
}

// itemList is a helper for printing out a nice error message when a resource is not found.
func itemList(resources []client.Object) string {
	items := []string{}
	for i, r := range resources {
		items = append(items,
			fmt.Sprintf("%d: %T Namespace=%s Name=%s",
				i,
				r,
				r.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
				r.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName(),
			))
	}
	return strings.Join(items, "\n")
}

// ExpectResourceTypeAndObjectMetadata checks that the given resource matches the expected name, namespace, group, version, and kind.
// Note that this function often results in tests that are brittle and subject to breakages when resource ordering changes, and are also hard to debug.
// most tests should use ExpectResources instead, which is more robust and provides better error messages.
// Use this function only when the order of resources is actually important.
func ExpectResourceTypeAndObjectMetadata(resource runtime.Object, name, ns, group, version, kind string) {
	gvk := schema.GroupVersionKind{Group: group, Version: version, Kind: kind}
	actualName := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
	actualNS := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()
	ExpectWithOffset(1, actualName).To(Equal(name), fmt.Sprintf("Rendered %s resource in namespace %s has wrong name", kind, ns))
	ExpectWithOffset(1, actualNS).To(Equal(ns), fmt.Sprintf("Rendered resource %s/%s has wrong namespace", kind, name))
	ExpectWithOffset(1, resource.GetObjectKind().GroupVersionKind()).To(Equal(gvk), fmt.Sprintf("Rendered resource %s does not match expected GVK", name))
}

// GetResource returns the resource with the given name, namespace, group, version, and kind from the given list of resources.
func GetResource(resources []client.Object, name, ns, group, version, kind string) client.Object {
	for _, resource := range resources {
		gvk := schema.GroupVersionKind{Group: group, Version: version, Kind: kind}
		om := resource.(metav1.ObjectMetaAccessor).GetObjectMeta()
		if name == om.GetName() &&
			ns == om.GetNamespace() &&
			gvk == resource.GetObjectKind().GroupVersionKind() {
			return resource
		}
	}
	return nil
}

func GetResourceOfType[T client.Object](resources []client.Object, name, ns string) (T, error) {
	for _, r := range resources {
		if reflect.TypeOf(r) != reflect.TypeOf(*new(T)) {
			continue
		}
		if r.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName() != name {
			continue
		}
		if r.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace() != ns {
			continue
		}
		// Type, name, and namespace match.
		return r.(T), nil
	}

	// Return a nil instance of T and an error.
	var n T
	return n, notFoundError(name, ns, n, resources)
}

func GetGlobalResource(resources []client.Object, name, group, version, kind string) client.Object {
	for _, resource := range resources {
		gvk := schema.GroupVersionKind{Group: group, Version: version, Kind: kind}
		om := resource.(metav1.ObjectMetaAccessor).GetObjectMeta()
		if name == om.GetName() &&
			gvk == resource.GetObjectKind().GroupVersionKind() {
			return resource
		}
	}
	return nil
}

func GetContainer(containers []corev1.Container, name string) *corev1.Container {
	for _, container := range containers {
		if container.Name == name {
			return &container
		}
	}
	return nil
}

func ExpectGlobalReportType(resource runtime.Object, name string) {
	actualName := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
	Expect(actualName).To(Equal(name), "Rendered resource has wrong name")
	gvk := schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "GlobalReportType"}
	Expect(resource.GetObjectKind().GroupVersionKind()).To(Equal(gvk), fmt.Sprintf("Rendered resource %s does not match expected GVK", name))
	v, ok := resource.(*v3.GlobalReportType)
	Expect(ok).To(BeTrue(), fmt.Sprintf("resource (%v) should convert to GlobalReportType", resource))
	Expect(v.Spec.UISummaryTemplate.Template).ToNot(BeEmpty())
	_, err := json.Marshal(v.Spec.UISummaryTemplate.Template)
	Expect(err).To(BeNil())
	for _, t := range v.Spec.DownloadTemplates {
		Expect(t.Template).ToNot(BeEmpty(), fmt.Sprintf("%s template should not be empty", t.Name))
		_, err = json.Marshal(t.Template)
		Expect(err).To(BeNil())
	}
}

func ExpectGlobalAlertTemplateToBePopulated(resource runtime.Object) {
	v, ok := resource.(*v3.GlobalAlertTemplate)
	Expect(ok).To(BeTrue(), fmt.Sprintf("resource (%v) should convert to GlobalAlertTemplate", resource))
	Expect(v.Spec.Description).ToNot(BeEmpty(), fmt.Sprintf("Description should not be empty for resource (%v)", resource))
	Expect(v.Spec.Severity).ToNot(BeNumerically("==", 0), fmt.Sprintf("Severity should not be empty for resource (%v)", resource))

	if v.Spec.Type != v3.GlobalAlertTypeAnomalyDetection { // ignored for  AnomalyDetection Typed
		Expect(v.Spec.DataSet).ToNot(BeEmpty(), fmt.Sprintf("DataSet should not be empty for resource (%v)", resource))
	}
}

func ExpectEnv(env []corev1.EnvVar, key, value string) {
	for _, e := range env {
		if e.Name == key {
			Expect(e.Value).To(Equal(value))
			return
		}
	}
	Expect(false).To(BeTrue(), fmt.Sprintf("Missing expected environment variable %s", key))
}

func ExpectVolumeMount(vms []corev1.VolumeMount, name, path string) {
	for _, vm := range vms {
		if vm.Name == name {
			Expect(vm.MountPath).To(Equal(path))
			return
		}
	}
	ExpectWithOffset(1, false).To(BeTrue(), fmt.Sprintf("Missing expected volume mount %s", name))
}

// CreateCertSecret creates a secret that is not signed by the certificate manager, making it useful for testing legacy
// operator secrets or secrets that are brought to the cluster by the customer.
func CreateCertSecret(name, namespace string, dnsNames ...string) *corev1.Secret {
	cryptoCA, _ := tls.MakeCA(rmeta.TigeraOperatorCAIssuerPrefix + "@some-hash")
	cfg, _ := cryptoCA.MakeServerCertForDuration(sets.New[string](dnsNames...), tls.DefaultCertificateDuration, tls.SetServerAuth, tls.SetClientAuth)
	keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
	_ = cfg.WriteCertConfig(crtContent, keyContent)

	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: keyContent.Bytes(),
			corev1.TLSCertKey:       crtContent.Bytes(),
		},
	}
}

func CreateCertSecretWithContent(name, namespace string, keyContent []byte, crtContent []byte) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: keyContent,
			corev1.TLSCertKey:       crtContent,
		},
	}
}

func ExpectBundleContents(bundle *corev1.ConfigMap, secrets ...types.NamespacedName) {
	ExpectWithOffset(1, bundle.Data).To(HaveKey(certificatemanagement.TrustedCertConfigMapKeyName), fmt.Sprintf("Bundle: %+v", bundle))

	// Go through and build up all of the secret names from within the bundle.
	// Keep a list of all the certificates in the bundle in case we need to error it out.
	certsInBundle := map[types.NamespacedName]bool{}

	// Use a regex to extract secret namespaces and names from the bundle by matching
	// the following pattern:
	// # certificate name: <namespace>/<name>
	re := regexp.MustCompile(`# certificate name: ([^\s]*)\/([^\s\n]*)`)
	matches := re.FindAllStringSubmatch(bundle.Data[certificatemanagement.TrustedCertConfigMapKeyName], -1)

	// Go through each match and add it to the list of certs in the bundle.
	for _, match := range matches {
		key := types.NamespacedName{Name: match[2], Namespace: match[1]}
		ExpectWithOffset(1, certsInBundle).ToNot(HaveKey(key), "Duplicate certificate found in bundle")
		certsInBundle[key] = true
	}

	// Local helper for erroring if a secret is not found in the bundle.
	errNotInBundle := func(s types.NamespacedName) string {
		errStr := fmt.Sprintf("Certificate %s/%s not found among those in bundle:\n\n", s.Namespace, s.Name)
		for cert := range certsInBundle {
			errStr += fmt.Sprintf("%s/%s\n", cert.Namespace, cert.Name)
		}
		return errStr
	}

	// Now, we can assert that each secret given as an argument to this function is in the bundle.
	for _, secret := range secrets {
		ExpectWithOffset(1, certsInBundle).To(HaveKey(secret), errNotInBundle(secret))
	}

	// We can also assert that each secret within the bundle was given as an argument to this function!
	for cert := range certsInBundle {
		found := false
		for _, secret := range secrets {
			if cert.Name == secret.Name && cert.Namespace == secret.Namespace {
				found = true
				break
			}
		}

		// If not found, error out.
		errStr := fmt.Sprintf("Unexpected certificate %s/%s found among those in bundle", cert.Namespace, cert.Name)
		ExpectWithOffset(1, found).To(BeTrue(), errStr)
	}
}
