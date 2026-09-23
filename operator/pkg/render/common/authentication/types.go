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

package authentication

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

type KeyValidatorConfig interface {
	Issuer() string
	ClientID() string
	// RequiredConfigMaps returns config maps that the KeyValidatorConfig implementation requires.
	RequiredConfigMaps(namespace string) []*corev1.ConfigMap
	// RequiredEnv returns env variables that the KeyValidatorConfig implementation requires.
	RequiredEnv(prefix string) []corev1.EnvVar
	// RequiredAnnotations returns annotations that the KeyValidatorConfig implementation requires.
	RequiredAnnotations() map[string]string
	// RequiredSecrets returns secrets that the KeyValidatorConfig implementation requires.
	RequiredSecrets(namespace string) []*corev1.Secret
	// RequiredVolumeMounts returns volume mounts that the KeyValidatorConfig implementation requires.
	RequiredVolumeMounts() []corev1.VolumeMount
	// RequiredVolumes returns volumes that the KeyValidatorConfig implementation requires.
	RequiredVolumes() []corev1.Volume
}

func NewWellKnownConfig(issuerURL string, rootCA []byte) (*WellKnownConfig, error) {
	httpClient := http.DefaultClient
	if len(rootCA) > 0 {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(rootCA)
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caCertPool},
		}
	}

	wellKnown := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	wellKnownConfig := WellKnownConfig{}
	if err = json.Unmarshal(body, &wellKnownConfig); err != nil {
		return nil, err
	}

	return &wellKnownConfig, nil
}

type WellKnownConfig struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

func (wk *WellKnownConfig) GetJWKS() ([]byte, error) {
	httpClient := http.DefaultClient

	req, err := http.NewRequest("GET", wk.JWKSURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	keys, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

func (wk *WellKnownConfig) ToString() string {
	str, err := json.Marshal(wk)
	if err != nil {
		// TODO rethink panicking
		panic(err)
	}

	return string(str)
}
