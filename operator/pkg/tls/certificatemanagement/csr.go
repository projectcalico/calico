// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package certificatemanagement

import (
	"encoding/base64"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
)

const (
	CSRClusterRoleName   = "tigera-csr-creator"
	CSRCMountPath        = "/certs-share"
	CSRInitContainerName = "key-cert-provisioner"
)

// CreateCSRInitContainer creates an init container that can be added to a pod spec in order to create a CSR for its
// TLS certificates. It uses the provided params and the k8s downward api to be able to specify certificate subject information.
// The init container dispatches into the combined calico/calico binary via the key-cert-provisioner Cobra subcommand.
func CreateCSRInitContainer(
	certificateManagement *operatorv1.CertificateManagement,
	secretName,
	image string,
	mountName string,
	commonName string,
	keyName string,
	certName string,
	dnsNames []string,
	appNameLabel string,
	securityContext *corev1.SecurityContext,
) corev1.Container {
	return corev1.Container{
		Name:    CSRInitContainerName,
		Image:   image,
		Command: []string{components.CalicoBinaryPath, "component", "key-cert-provisioner"},
		VolumeMounts: []corev1.VolumeMount{
			{MountPath: CSRCMountPath, Name: mountName, ReadOnly: false},
		},
		Env: []corev1.EnvVar{
			{Name: "CERTIFICATE_PATH", Value: "/certs-share/"},
			// SecretName, when defined, is used as a prefix for the CSR name. This avoids CSR name clashes if the same
			// pod issues more than one CSR. Even though the CSRs are issued and read in sequence, there are edge-cases
			// where a pod can get stuck in init.
			{Name: "SECRET_NAME", Value: secretName},
			{Name: "SIGNER", Value: certificateManagement.SignerName},
			{Name: "COMMON_NAME", Value: commonName},
			{Name: "KEY_ALGORITHM", Value: fmt.Sprintf("%v", certificateManagement.KeyAlgorithm)},
			{Name: "SIGNATURE_ALGORITHM", Value: fmt.Sprintf("%v", certificateManagement.SignatureAlgorithm)},
			{Name: "KEY_NAME", Value: keyName},
			{Name: "CERT_NAME", Value: certName},
			{Name: "CA_CERT_NAME", Value: "ca.crt"},
			{Name: "CA_CERT", Value: base64.URLEncoding.EncodeToString(certificateManagement.CACert)},
			{Name: "APP_NAME", Value: appNameLabel},
			{Name: "DNS_NAMES", Value: strings.Join(dnsNames, ",")},
			{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "status.podIP",
				},
			}},
			{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			}},
			{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.namespace",
				},
			}},
		},
		SecurityContext: securityContext,
		Resources:       components.GetCSRContainerDefaultResources(),
	}
}

// ResolveCSRInitImage resolves the image needed for the CSR init container, taking into account the
// specified ImageSet. The init container reuses the combined calico/calico image and dispatches into
// the key-cert-provisioner Cobra subcommand.
func ResolveCSRInitImage(inst *operatorv1.InstallationSpec, is *operatorv1.ImageSet) (string, error) {
	return components.GetReference(components.CombinedCalicoImage(inst), inst.Registry, inst.ImagePath, inst.ImagePrefix, is)
}

// CSRClusterRole returns a role with the necessary permissions to create certificate signing requests.
func CSRClusterRole() client.Object {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   CSRClusterRoleName,
			Labels: map[string]string{},
		},

		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"certificates.k8s.io"},
				Resources: []string{"certificatesigningrequests"},
				Verbs:     []string{"create", "watch", "delete"},
			},
		},
	}
}

// CSRClusterRoleBinding returns a role binding with the necessary permissions to create certificate signing requests.
func CSRClusterRoleBinding(name, namespace string) *rbacv1.ClusterRoleBinding {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   fmt.Sprintf("%s:csr-creator", name),
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     CSRClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      name,
				Namespace: namespace,
			},
		},
	}
	return crb
}

func CertificateVolumeSource(certificateManagement *operatorv1.CertificateManagement, secretName string) corev1.VolumeSource {
	var defaultMode int32 = 420
	if certificateManagement != nil {
		return corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				// Writing the TLS assets to memory. This is more secure and less accessible.
				Medium: corev1.StorageMediumMemory,
			},
		}
	} else {
		return corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName:  secretName,
				DefaultMode: &defaultMode,
			},
		}
	}
}
