// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package render

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
)

func AWSSecurityGroupSetup(cfg *AWSSGSetupConfiguration) (Component, error) {
	return &awsSGSetupComponent{cfg: cfg}, nil
}

// AWSSGSetupConfiguration contains all the config information needed to render the component.
type AWSSGSetupConfiguration struct {
	PullSecrets     []corev1.LocalObjectReference
	Installation    *operatorv1.InstallationSpec
	HostedOpenShift bool
}

type awsSGSetupComponent struct {
	cfg   *AWSSGSetupConfiguration
	image string
}

func (c *awsSGSetupComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *awsSGSetupComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	c.image, err = components.GetReference(components.ComponentOperatorInit, reg, path, prefix, is)
	return err
}

func (c *awsSGSetupComponent) Objects() ([]client.Object, []client.Object) {
	return []client.Object{
		c.serviceAccount(),
		c.role(),
		c.roleBinding(),
		c.setupJob(),
	}, nil
}

func (c *awsSGSetupComponent) Ready() bool {
	return true
}

func (c *awsSGSetupComponent) setupJob() *batchv1.Job {
	envVars := []corev1.EnvVar{
		{
			Name:  "OPENSHIFT",
			Value: "true",
		},
		{
			Name:  "REQUIRE_AWS",
			Value: "true",
		},
		{
			Name:  "KUBELET_KUBECONFIG",
			Value: "/etc/kubernetes/kubeconfig",
		},
	}

	if c.cfg.HostedOpenShift {
		envVars = append(envVars, corev1.EnvVar{
			Name:  "HOSTED_OPENSHIFT",
			Value: "true",
		})
	}
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aws-security-group-setup-1",
			Namespace: common.OperatorNamespace(),
		},
		Spec: batchv1.JobSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"job-name": "aws-security-group-setup-1",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"job-name": "aws-security-group-setup-1"},
				},
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyOnFailure,
					ImagePullSecrets:   c.cfg.PullSecrets,
					ServiceAccountName: TigeraAWSSGSetupName,
					HostNetwork:        true,
					Tolerations:        rmeta.TolerateAll,
					Containers: []corev1.Container{{
						Name:            "aws-security-group-setup",
						Image:           c.image,
						Args:            []string{"--aws-sg-setup"},
						Env:             envVars,
						SecurityContext: securitycontext.NewNonRootContext(),
					}},
				},
			},
		},
	}
}

const TigeraAWSSGSetupName = "tigera-aws-security-group-setup"

func (c *awsSGSetupComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraAWSSGSetupName,
			Namespace: common.OperatorNamespace(),
		},
	}
}

// roleBinding creates a clusterrolebinding giving the node service account the required permissions to operate.
func (c *awsSGSetupComponent) roleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraAWSSGSetupName,
			Namespace: metav1.NamespaceSystem,
			Labels:    map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     TigeraAWSSGSetupName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      TigeraAWSSGSetupName,
				Namespace: common.OperatorNamespace(),
			},
		},
	}
}

// nodeRole creates the clusterrole containing policy rules that allow the node daemonset to operate normally.
func (c *awsSGSetupComponent) role() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraAWSSGSetupName,
			Namespace: metav1.NamespaceSystem,
			Labels:    map[string]string{},
		},

		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{"aws-creds"},
				Verbs:         []string{"get"},
			},
		},
	}
}
