// Package charttest uses 'helm template' to render the helm package with various input values,
// unmarshals the resulting yaml into kubernetes resource types, and then tests that the correct fields
// are set accordingly.
package charttest

import (
	"path/filepath"

	corev1 "k8s.io/api/core/v1"

	"github.com/gruntwork-io/terratest/modules/helm"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func renderObj(options *helm.Options, templatePath string, into any) error {
	helmChartPath, err := filepath.Abs("../tigera-operator")
	Expect(err).ToNot(HaveOccurred())

	output, err := helm.RenderTemplateE(GinkgoT(), options, helmChartPath, "tigera-operator", []string{templatePath})
	if err != nil {
		return err
	}
	helm.UnmarshalK8SYaml(GinkgoT(), output, &into)
	return nil
}

var _ = Describe("Tigera Operator Helm Chart", func() {
	Describe("image pull secrets", func() {
		Context("using toplevel config field", func() {
			opts := &helm.Options{
				SetValues: map[string]string{
					"imagePullSecrets.my-secret": "secret1",
				},
			}

			It("sets imagePullSecrets on serviceaccount", func() {
				var serviceAccount corev1.ServiceAccount
				err := renderObj(opts, "templates/tigera-operator/02-serviceaccount-tigera-operator.yaml", &serviceAccount)
				Expect(err).ToNot(HaveOccurred())
				Expect(serviceAccount.ImagePullSecrets).To(ConsistOf(
					corev1.LocalObjectReference{Name: "my-secret"},
				))
			})

			It("creates a secret", func() {
				var secret corev1.Secret
				err := renderObj(opts, "templates/tigera-operator/01-imagepullsecret.yaml", &secret)
				Expect(err).ToNot(HaveOccurred())
				Expect(secret.Name).To(Equal("my-secret"))
				Expect(secret.Data).To(Equal(map[string][]byte{
					".dockerconfigjson": []byte("secret1"),
				}))
			})
		})

		Context("using installation's config field", func() {
			opts := &helm.Options{
				SetValues: map[string]string{
					"installation.imagePullSecrets[0].name": "my-secret",
				},
			}

			It("sets imagePullSecrets on serviceaccount", func() {
				var serviceAccount corev1.ServiceAccount
				err := renderObj(opts, "templates/tigera-operator/02-serviceaccount-tigera-operator.yaml", &serviceAccount)
				Expect(err).ToNot(HaveOccurred())
				Expect(serviceAccount.ImagePullSecrets).To(ConsistOf(
					corev1.LocalObjectReference{Name: "my-secret"},
				))
			})

			It("does not create a secret", func() {
				// assert an error occured. no other way to assert "file was not rendered"
				err := renderObj(opts, "templates/tigera-operator/01-imagepullsecret.yaml", &corev1.Secret{})
				Expect(err).To(HaveOccurred())
			})
		})

		Describe("using both toplevel and installation fields", func() {
			opts := &helm.Options{
				SetValues: map[string]string{
					"imagePullSecrets.secret-1":             "secret1",
					"installation.imagePullSecrets[0].name": "secret-2",
				},
			}

			It("sets both imagePullSecrets on serviceaccount", func() {
				var serviceAccount corev1.ServiceAccount
				err := renderObj(opts, "templates/tigera-operator/02-serviceaccount-tigera-operator.yaml", &serviceAccount)
				Expect(err).ToNot(HaveOccurred())
				Expect(serviceAccount.ImagePullSecrets).To(ConsistOf(
					corev1.LocalObjectReference{Name: "secret-1"},
					corev1.LocalObjectReference{Name: "secret-2"},
				))
			})

			It("only creates a secret for the toplevel secret", func() {
				var secret corev1.Secret
				err := renderObj(opts, "templates/tigera-operator/01-imagepullsecret.yaml", &secret)
				Expect(err).ToNot(HaveOccurred())
				Expect(secret.Name).To(Equal("secret-1"))
				Expect(secret.Data).To(Equal(map[string][]byte{
					".dockerconfigjson": []byte("secret1"),
				}))
			})
		})
	})
})
