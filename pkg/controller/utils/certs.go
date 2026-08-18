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

package utils

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

func GetSecret(ctx context.Context, client client.Client, name string, ns string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, secret); err != nil {
		if !kerrors.IsNotFound(err) {
			return nil, err
		}
		return nil, nil
	}
	return secret, nil
}

// ParseCommonNameAndURISAN reads the common name and first URI SAN out of a BYO
// certificate secret.
func ParseCommonNameAndURISAN(secret *corev1.Secret) (cn, urisan string, err error) {
	certData, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return "", "", fmt.Errorf("failed to find cert data in secret")
	}

	cert, err := certificatemanagement.ParseCertificate(certData)
	if err != nil {
		return "", "", err
	}

	cn = cert.Subject.CommonName
	if len(cert.URIs) > 0 {
		urisan = cert.URIs[0].String()
	}
	return cn, urisan, nil
}
