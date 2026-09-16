// Package charttest uses 'helm template' to render the helm package with various input values,
// unmarshals the resulting yaml into kubernetes resource types, and then tests that the correct fields
// are set accordingly.
package charttest

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/gruntwork-io/terratest/modules/k8s"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// TestMain creates a dummy tigera-prometheus-operator subchart so helm can load
// the tigera-operator chart. Chart.yaml declares it as a dependency, and helm
// verifies declared dependencies are present in charts/ before rendering
// anything
func TestMain(m *testing.M) {
	const chartsDir = "../tigera-operator/charts"
	var createdDepDir []string

	// copy tigera-prometheus-operator/Chart.yaml to
	// tigera-operator/charts/tigera-prometheus-operator/Chart.yaml (if exists)
	for _, dep := range []string{"tigera-prometheus-operator"} {
		src := filepath.Join("..", dep, "Chart.yaml")
		if _, err := os.Stat(src); err != nil {
			continue // subchart not present in this repo
		}
		stub := filepath.Join(chartsDir, dep)
		if err := os.MkdirAll(stub, 0o755); err != nil {
			panic(err)
		}
		b, err := os.ReadFile(src)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(stub, "Chart.yaml"), b, 0o644); err != nil {
			panic(err)
		}
		createdDepDir = append(createdDepDir, stub)
	}

	code := m.Run()

	for _, dep := range createdDepDir {
		os.RemoveAll(dep)
	}

	os.Remove(chartsDir)
	os.Exit(code)
}

func TestTigeraOperatorHelmChart(t *testing.T) {
	const namespace = "tigera-operator"
	anySecret := func(s corev1.Secret) bool { return s.Kind == "Secret" }
	anyServiceAccount := func(sa corev1.ServiceAccount) bool { return sa.Kind == "ServiceAccount" }
	operatorServiceAccount := func(sa corev1.ServiceAccount) bool {
		return sa.Kind == "ServiceAccount" && sa.Name == namespace
	}
	t.Run("image pull secrets", func(t *testing.T) {
		t.Run("using toplevel config field", func(t *testing.T) {
			opts := &helm.Options{
				SetValues: map[string]string{
					"imagePullSecrets.my-secret": "secret1",
				},
			}

			t.Run("sets imagePullSecrets on serviceaccount", func(t *testing.T) {
				g := NewWithT(t)

				serviceAccounts, err := renderObjects(t, opts, operatorServiceAccount)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(serviceAccounts).To(HaveLen(1))
				g.Expect(serviceAccounts[0].ImagePullSecrets).To(ConsistOf(
					corev1.LocalObjectReference{Name: "my-secret"},
				))
			})

			t.Run("creates a secret", func(t *testing.T) {
				g := NewWithT(t)

				secrets, err := renderObjects(t, opts, anySecret)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(secrets).To(HaveLen(1))
				g.Expect(secrets[0].Name).To(Equal("my-secret"))
				g.Expect(secrets[0].Data).To(Equal(map[string][]byte{
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

				serviceAccounts, err := renderObjects(t, opts, anyServiceAccount)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(serviceAccounts).To(HaveLen(1))
				g.Expect(serviceAccounts[0].ImagePullSecrets).To(ConsistOf(
					corev1.LocalObjectReference{Name: "my-secret"},
				))
			})

			t.Run("does not create a secret", func(t *testing.T) {
				g := NewWithT(t)
				secrets, err := renderObjects(t, opts, anySecret)
				// assert an error occurred. no other way to assert "file was not rendered"
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(secrets).To(BeEmpty())
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

				serviceAccounts, err := renderObjects(t, opts, operatorServiceAccount)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(serviceAccounts).To(HaveLen(1))
				g.Expect(serviceAccounts[0].ImagePullSecrets).To(ConsistOf(
					corev1.LocalObjectReference{Name: "secret-1"},
					corev1.LocalObjectReference{Name: "secret-2"},
				))
			})

			t.Run("only creates a secret for the toplevel secret", func(t *testing.T) {
				g := NewWithT(t)

				secrets, err := renderObjects(t, opts, anySecret)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(secrets).To(HaveLen(1))
				g.Expect(secrets[0].Name).To(Equal("secret-1"))
				g.Expect(secrets[0].Data).To(Equal(map[string][]byte{
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

func TestOperatorServiceAccountNaming(t *testing.T) {
	const (
		operatorName = "tigera-operator"
		secretsName  = "tigera-operator-secrets"
	)

	for _, ns := range []string{
		"tigera-operator",
		"tigera-operator-enterprise",
		"tigera-operator-some-other-namespace",
	} {
		t.Run("namespace="+ns, func(t *testing.T) {
			g := NewWithT(t)
			opts := &helm.Options{KubectlOptions: k8s.NewKubectlOptions("", "", ns)}

			serviceAccounts, err := renderObjects(t, opts, isServiceAccount)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(serviceAccounts).To(HaveLen(1))
			g.Expect(serviceAccounts[0].Name).To(Equal(operatorName),
				"ServiceAccount name must not follow the release namespace")
			g.Expect(serviceAccounts[0].Namespace).To(Equal(ns))

			deploys, err := renderObjects(t, opts, isDeployment)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(deploys).To(HaveLen(1))
			g.Expect(deploys[0].Name).To(Equal(operatorName))
			g.Expect(deploys[0].Namespace).To(Equal(ns))
			g.Expect(deploys[0].Spec.Template.Spec.ServiceAccountName).To(Equal(serviceAccounts[0].Name),
				"Deployment must run as the ServiceAccount this chart creates")

			wantSubject := rbacv1.Subject{Kind: "ServiceAccount", Name: serviceAccounts[0].Name, Namespace: ns}

			roleBindings, err := renderObjects(t, opts, isRoleBinding)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(roleBindings).To(HaveLen(1))
			g.Expect(roleBindings[0].Name).To(Equal(secretsName))
			g.Expect(roleBindings[0].Namespace).To(Equal(ns))
			g.Expect(roleBindings[0].Subjects).To(ConsistOf(wantSubject))

			clusterRoleBindings, err := renderObjects(t, opts, isClusterRoleBinding)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(clusterRoleBindings).To(HaveLen(1))
			g.Expect(clusterRoleBindings[0].Subjects).To(ConsistOf(wantSubject))

			jobs, err := renderObjects(t, opts, isJob)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(jobs).To(HaveLen(1), "the pre-delete uninstall hook")
			g.Expect(jobs[0].Name).To(Equal("tigera-operator-uninstall"))
			g.Expect(jobs[0].Spec.Template.Spec.ServiceAccountName).To(Equal(serviceAccounts[0].Name))

			clusterRoles, err := renderObjects(t, opts, isClusterRole)
			g.Expect(err).NotTo(HaveOccurred())

			i := slices.IndexFunc(clusterRoles, func(cr rbacv1.ClusterRole) bool { return cr.Name == clusterRoleBindings[0].RoleRef.Name })
			g.Expect(i).To(BeNumerically(">=", 0))
			g.Expect(finalizerResourceNames(clusterRoles[i])).To(ConsistOf(deploys[0].Name),
				"deployments/finalizers resourceNames must name the Deployment, not the namespace")

		})
	}
}

func finalizerResourceNames(cr rbacv1.ClusterRole) []string {
	var names []string
	for _, rule := range cr.Rules {
		if slices.Contains(rule.Resources, "deployments/finalizers") {
			names = append(names, rule.ResourceNames...)
		}
	}
	return names
}
