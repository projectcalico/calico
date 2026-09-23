package charttest

import (
	"path/filepath"
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// renderObjects runs `helm template` over the whole chart and returns every
// rendered object.
//
// The chart is rendered as a whole rather than by naming template files.
func renderObjects[T any](t *testing.T, options *helm.Options, keep func(T) bool) ([]T, error) {
	chartDir, err := filepath.Abs("../tigera-operator")
	if err != nil {
		return nil, err
	}

	// A nil templateFiles means render everything.
	output, err := helm.RenderTemplateContextE(t, t.Context(), options, chartDir, "tigera-operator", nil)
	if err != nil {
		return nil, err
	}

	var objs []T

	_ = helm.UnmarshalK8SYamlsE(t, output, &objs, keep)
	return objs, nil
}

func isServiceAccount(o corev1.ServiceAccount) bool         { return o.Kind == "ServiceAccount" }
func isSecret(o corev1.Secret) bool                         { return o.Kind == "Secret" }
func isDeployment(o appsv1.Deployment) bool                 { return o.Kind == "Deployment" }
func isJob(o batchv1.Job) bool                              { return o.Kind == "Job" }
func isRoleBinding(o rbacv1.RoleBinding) bool               { return o.Kind == "RoleBinding" }
func isClusterRole(o rbacv1.ClusterRole) bool               { return o.Kind == "ClusterRole" }
func isClusterRoleBinding(o rbacv1.ClusterRoleBinding) bool { return o.Kind == "ClusterRoleBinding" }
