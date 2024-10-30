// Package charttest uses 'helm template' to render the helm package with various input values,
// unmarshals the resulting yaml into kubernetes resource types, and then tests that the correct fields
// are set accordingly.
package charttest

import (
	"path/filepath"
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

func TestTigeraOperatorHelmChart(t *testing.T) {
	t.Run("image pull secrets", func(t *testing.T) {
		t.Run("using toplevel config field", func(t *testing.T) {
			opts := &helm.Options{
				SetValues: map[string]string{
					"imagePullSecrets.my-secret": "secret1",
				},
			}

			t.Run("sets imagePullSecrets on serviceaccount", func(t *testing.T) {
				g := NewWithT(t)
				var serviceAccount corev1.ServiceAccount
				err := renderChartResource(t, opts, "templates/tigera-operator/02-serviceaccount-tigera-operator.yaml", &serviceAccount)
				g.Expect(err).To(HaveOccurred())
				g.Expect(serviceAccount.ImagePullSecrets).To(ConsistOf(
					corev1.LocalObjectReference{Name: "my-secret"},
				))
			})

			t.Run("creates a secret", func(t *testing.T) {
				g := NewWithT(t)
				var secret corev1.Secret
				err := renderChartResource(t, opts, "templates/tigera-operator/01-imagepullsecret.yaml", &secret)
				g.Expect(err).To(HaveOccurred())
				g.Expect(secret.Name).To(Equal("my-secret"))
				g.Expect(secret.Data).To(Equal(map[string][]byte{
					".dockerconfigjson": []byte("secret1"),
				}))
			})
		})

		t.Run("using installation's config field", func(t *testing.T) {
			opts := &helm.Options{
				SetValues: map[string]string{
					"installation.imagePullSecrets[0].name": "my-secret",
				},
			}

			t.Run("sets imagePullSecrets on serviceaccount", func(t *testing.T) {
				g := NewWithT(t)
				var serviceAccount corev1.ServiceAccount
				err := renderChartResource(t, opts, "templates/tigera-operator/02-serviceaccount-tigera-operator.yaml", &serviceAccount)
				g.Expect(err).To(HaveOccurred())
				g.Expect(serviceAccount.ImagePullSecrets).To(ConsistOf(
					corev1.LocalObjectReference{Name: "my-secret"},
				))
			})

			t.Run("does not create a secret", func(t *testing.T) {
				g := NewWithT(t)
				// assert an error occurred. no other way to assert "file was not rendered"
				err := renderChartResource(t, opts, "templates/tigera-operator/01-imagepullsecret.yaml", &corev1.Secret{})
				g.Expect(err).To(HaveOccurred())
			})
		})

		t.Run("using both toplevel and installation fields", func(t *testing.T) {
			opts := &helm.Options{
				SetValues: map[string]string{
					"imagePullSecrets.secret-1":             "secret1",
					"installation.imagePullSecrets[0].name": "secret-2",
				},
			}

			t.Run("sets both imagePullSecrets on serviceaccount", func(t *testing.T) {
				g := NewWithT(t)
				var serviceAccount corev1.ServiceAccount
				err := renderChartResource(t, opts, "templates/tigera-operator/02-serviceaccount-tigera-operator.yaml", &serviceAccount)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(serviceAccount.ImagePullSecrets).To(ConsistOf(
					corev1.LocalObjectReference{Name: "secret-1"},
					corev1.LocalObjectReference{Name: "secret-2"},
				))
			})

			t.Run("only creates a secret for the toplevel secret", func(t *testing.T) {
				g := NewWithT(t)
				var secret corev1.Secret
				err := renderChartResource(t, opts, "templates/tigera-operator/01-imagepullsecret.yaml", &secret)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(secret.Name).To(Equal("secret-1"))
				g.Expect(secret.Data).To(Equal(map[string][]byte{
					".dockerconfigjson": []byte("secret1"),
				}))
			})
		})
	})
}

func renderChartResource(t *testing.T, options *helm.Options, templatePath string, into any) error {
	helmChartPath, err := filepath.Abs("../tigera-operator")
	Expect(err).ToNot(HaveOccurred())

	output, err := helm.RenderTemplateE(t, options, helmChartPath, "tigera-operator", []string{templatePath})
	if err != nil {
		return err
	}
	helm.UnmarshalK8SYaml(t, output, &into)
	return nil
}
