// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package secret

import (
	"bytes"
	"fmt"
	"time"

	csisecret "sigs.k8s.io/secrets-store-csi-driver/apis/v1"

	"github.com/openshift/library-go/pkg/crypto"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CreateTLSSecret Creates a new TLS secret with the information passed
//
//	ca: The ca to use for creating the Cert/Key pair. This is required.
//	secretName: The name of the secret.
//	secretKeyName: The name of the data field that will contain the key.
//	secretCertName: The name of the data field that will contain the cert.
//	dur: How long the certificate will be valid.
//	hostnames: The first will be used as the CN, and the rest as SANs. If
//	  no hostnames are provided then "localhost" will be used.
//
// The first hostname provided is used as the common name for the certificate. If hostnames are not provided, localhost
// is used. This code came from:
// https://github.com/openshift/library-go/blob/84f02c4b7d6ab9d67f63b13586693600051de401/pkg/controller/controllercmd/cmd.go#L153
func CreateTLSSecret(
	ca *crypto.CA,
	secretName, secretNamespace, secretKeyName, secretCertName string,
	dur time.Duration,
	cef []crypto.CertificateExtensionFunc,
	hostnames ...string,
) (*corev1.Secret, error) {
	var err error
	if ca == nil {
		ca, err = tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		if err != nil {
			return nil, fmt.Errorf("unable to create signed cert pair: %s", err)
		}
	}

	// localhost is the default hostname for the generated certificate if none are provided.
	hostnamesSet := sets.New[string]("localhost")
	if len(hostnames) > 0 {
		hostnamesSet = sets.New[string](hostnames...)
	}

	// Default extensions if not provided such that the certificate is valid
	// for both a server and client certificate.
	if len(cef) == 0 {
		cef = []crypto.CertificateExtensionFunc{tls.SetClientAuth, tls.SetServerAuth}
	}

	cert, err := ca.MakeServerCertForDuration(hostnamesSet, dur, cef...)
	if err != nil {
		return nil, fmt.Errorf("unable to create signed cert pair: %s", err)
	}

	return getSecretFromTLSConfig(cert, secretName, secretNamespace, secretKeyName, secretCertName)
}

func getSecretFromTLSConfig(
	tls *crypto.TLSCertificateConfig, secretName, secretNamespace, secretKeyName, secretCertName string,
) (*corev1.Secret, error) {
	crtContent := &bytes.Buffer{}
	keyContent := &bytes.Buffer{}
	if err := tls.WriteCertConfig(crtContent, keyContent); err != nil {
		return nil, err
	}

	data := make(map[string][]byte)
	data[secretKeyName] = keyContent.Bytes()
	data[secretCertName] = crtContent.Bytes()
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: secretNamespace,
		},
		Data: data,
	}, nil
}

// CopyToNamespace returns a new list of secrets generated from the ones given but with the namespace changed to the
// given one.
func CopyToNamespace(ns string, oSecrets ...*corev1.Secret) []*corev1.Secret {
	var secrets []*corev1.Secret
	for _, s := range oSecrets {
		x := s.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: ns}

		secrets = append(secrets, x)
	}
	return secrets
}

// ToRuntimeObjects converts the given list of secrets to a list of client.Objects
func ToRuntimeObjects(secrets ...*corev1.Secret) []client.Object {
	var objs []client.Object
	for _, secret := range secrets {
		if secret == nil {
			continue
		}
		objs = append(objs, secret)
	}
	return objs
}

// CopySecretProviderClassToNamespace returns a new list of SecretProviderClassToNamespace generated from the ones given but with the namespace changed to the
// given one.
func CopySecretProviderClassToNamespace(ns string, oSecrets ...*csisecret.SecretProviderClass) []*csisecret.SecretProviderClass {
	var secrets []*csisecret.SecretProviderClass
	for _, s := range oSecrets {
		x := s.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: ns}

		secrets = append(secrets, x)
	}
	return secrets
}

// ToSecretProviderClassRuntimeObjects converts the given list of SecretProviderClass to a list of client.Objects
func ToSecretProviderClassRuntimeObjects(secrets ...*csisecret.SecretProviderClass) []client.Object {
	var objs []client.Object
	for _, secret := range secrets {
		if secret == nil {
			continue
		}
		objs = append(objs, secret)
	}
	return objs
}

// GetEnvVarSource returns an EnvVarSource using the given secret name and key.
func GetEnvVarSource(secretName, key string, optional bool) *corev1.EnvVarSource {
	var opt *bool
	if optional {
		real := optional
		opt = &real
	}
	return &corev1.EnvVarSource{
		SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: secretName,
			},
			Key:      key,
			Optional: opt,
		},
	}
}

// GetReferenceList retrieves the object references from the secrets and returns that list.
func GetReferenceList(secrets []*corev1.Secret) []corev1.LocalObjectReference {
	var ps []corev1.LocalObjectReference
	for _, x := range secrets {
		ps = append(ps, corev1.LocalObjectReference{Name: x.Name})
	}
	return ps
}
