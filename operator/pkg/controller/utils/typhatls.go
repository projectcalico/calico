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

package utils

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

func GetOrCreateTyphaNodeTLSConfig(cli client.Client, certificateManager certificatemanager.CertificateManager) (*render.TyphaNodeTLS, error) {
	return getOrCreateTyphaNodeTLSConfig(cli, certificateManager, certificateManager.GetOrCreateKeyPair)
}

func GetTyphaNodeTLSConfig(cli client.Client, certificateManager certificatemanager.CertificateManager) (*render.TyphaNodeTLS, error) {
	return getOrCreateTyphaNodeTLSConfig(cli, certificateManager, certificateManager.GetKeyPair)
}

// getOrCreateTyphaNodeTLSConfig reads and validates the CA ConfigMap and Secrets for
// Typha and Felix configuration. It returns the validated resources or error
// if there was one.
func getOrCreateTyphaNodeTLSConfig(cli client.Client, certificateManager certificatemanager.CertificateManager, createKeyPairFunc func(cli client.Client, secretName, secretNamespace string, dnsNames []string) (certificatemanagement.KeyPairInterface, error)) (*render.TyphaNodeTLS, error) {
	// accumulate all the error messages so all problems with the certs
	// and CA are reported.
	var errMsgs []string
	getOrCreateKeyPair := func(secretName, commonName string, requireCNOrURISAN bool) (keyPair certificatemanagement.KeyPairInterface, cn string, uriSAN string) {
		keyPair, err := createKeyPairFunc(cli, secretName, common.OperatorNamespace(), []string{commonName})
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		} else {

			if !keyPair.BYO() {
				cn = commonName
			} else {
				// todo: Integrate this with the new certificate manager or find another alternative for uriSAN and cn.
				secret, err := GetSecret(context.Background(), cli, secretName, common.OperatorNamespace())
				if err != nil {
					errMsgs = append(errMsgs, err.Error())
				} else if secret != nil {
					data := secret.Data
					if data != nil {
						cn, uriSAN = string(data[render.CommonName]), string(data[render.URISAN])
					}
				}
			}
			if requireCNOrURISAN && cn == "" && uriSAN == "" {
				errMsgs = append(errMsgs, "CertPair for Felix does not contain common-name or uri-san")
			}
		}
		return
	}
	node, nodeCommonName, nodeURISAN := getOrCreateKeyPair(render.NodeTLSSecretName, render.FelixCommonName, true)
	typha, typhaCommonName, typhaURISAN := getOrCreateKeyPair(render.TyphaTLSSecretName, render.TyphaCommonName, true)
	var trustedBundle certificatemanagement.TrustedBundle
	configMap, err := GetOperatorConfigMap(cli, render.TyphaCAConfigMapName)
	if err != nil {
		errMsgs = append(errMsgs, fmt.Sprintf("CA for Typha is invalid: %s", err))
	} else if configMap != nil {
		if len(configMap.Data[render.TyphaCABundleName]) == 0 {
			errMsgs = append(errMsgs, fmt.Sprintf("ConfigMap %q does not have a field named %q", render.TyphaCAConfigMapName, render.TyphaCABundleName))
		} else {
			trustedBundle, err = certificateManager.CreateTrustedBundleWithSystemRootCertificates(node, typha,
				certificatemanagement.NewCertificate(render.TyphaCAConfigMapName, common.CalicoNamespace, []byte(configMap.Data[render.TyphaCABundleName]), nil))
			if err != nil {
				errMsgs = append(errMsgs, fmt.Sprintf("Error creating trusted bundle %s", err))
			}
		}
	} else {
		trustedBundle, err = certificateManager.CreateTrustedBundleWithSystemRootCertificates(node, typha)
		if err != nil {
			errMsgs = append(errMsgs, fmt.Sprintf("Error creating trusted bundle %s", err))
		}
	}
	if len(errMsgs) != 0 {
		return nil, fmt.Errorf("%s", strings.Join(errMsgs, ";"))
	}
	return &render.TyphaNodeTLS{
		TrustedBundle:   trustedBundle,
		TyphaSecret:     typha,
		TyphaCommonName: typhaCommonName,
		TyphaURISAN:     typhaURISAN,
		NodeSecret:      node,
		NodeCommonName:  nodeCommonName,
		NodeURISAN:      nodeURISAN,
	}, nil
}

// GetOperatorConfigMap reads a ConfigMap from the operator namespace, returning nil
// when it does not exist.
func GetOperatorConfigMap(client client.Client, cmName string) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      cmName,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read ConfigMap %q: %s", cmName, err)
	}
	return cm, nil
}
