// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-ldap/ldap"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"k8s.io/apimachinery/pkg/api/errors"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rauth "github.com/tigera/operator/pkg/render/common/authentication"
	tigerakvc "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
	csisecret "sigs.k8s.io/secrets-store-csi-driver/apis/v1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetKeyValidatorConfig uses the operatorv1.Authentication CR given to create the KeyValidatorConfig. This may be
// either a DexKeyValidatorConfig or a tigerakvc.KeyValidatorConfig.
//
// addTenancyClaim must only be set for Calico Cloud single-tenant management clusters; when true the
// KeyValidatorConfig is configured to require the cloud tenant claim (read from the cloud-auth-config
// ConfigMap). Regular Calico/Calico Enterprise callers pass false, leaving behavior unchanged.
func GetKeyValidatorConfig(ctx context.Context, cli client.Client, authenticationCR *operatorv1.Authentication, clusterDomain string, addTenancyClaim bool) (rauth.KeyValidatorConfig, error) {
	var keyValidatorConfig rauth.KeyValidatorConfig
	if authenticationCR != nil {
		_, idpSecret, err := GetSecretOrProviderClass(ctx, cli, authenticationCR)
		if err != nil {
			return nil, err
		}

		oidc := authenticationCR.Spec.OIDC
		if oidc != nil && oidc.Type == operatorv1.OIDCTypeTigera {
			var kvcOptions []tigerakvc.Option

			if addTenancyClaim {
				cloudOption, err := getCloudKeyValidatorOption(ctx, cli)
				if err != nil {
					return nil, err
				}
				kvcOptions = append(kvcOptions, cloudOption)
			}

			if oidc.UsernameClaim != "" {
				kvcOptions = append(kvcOptions, tigerakvc.WithUsernameClaim(oidc.UsernameClaim))
			}
			if oidc.GroupsClaim != "" {
				kvcOptions = append(kvcOptions, tigerakvc.WithGroupsClaim(oidc.GroupsClaim))
			}
			if oidc.UsernamePrefix != "" {
				kvcOptions = append(kvcOptions, tigerakvc.WithUsernamePrefix(oidc.UsernamePrefix))
			}
			if oidc.GroupsPrefix != "" {
				kvcOptions = append(kvcOptions, tigerakvc.WithGroupsPrefix(oidc.GroupsPrefix))
			}

			if rootCA, found := idpSecret.Data[render.RootCASecretField]; found {
				kvcOptions = append(kvcOptions, tigerakvc.WithRootCA(rootCA))
			}
			keyValidatorConfig, err = tigerakvc.New(oidc.IssuerURL, string(idpSecret.Data["clientID"]), kvcOptions...)
			if err != nil {
				return nil, err
			}
		} else {
			keyValidatorConfig = render.NewDexKeyValidatorConfig(authenticationCR, clusterDomain)
		}
	}

	return keyValidatorConfig, nil
}

func GetSecretOrProviderClass(ctx context.Context, client client.Client, authentication *operatorv1.Authentication) (*csisecret.SecretProviderClass, *corev1.Secret, error) {
	secretProviderClass, getSpcErr := GetSecretProviderClass(ctx, client, authentication)
	idpSecret, getIdpSecretErr := GetIDPSecret(ctx, client, authentication)
	if secretProviderClass != nil {
		if idpSecret != nil {
			log.Error(
				fmt.Errorf("both secret and provider class found for authentication, using provider class"),
				"a misconfiguration was detected for authentication")
		}
		return secretProviderClass, nil, getSpcErr
	}
	return nil, idpSecret, getIdpSecretErr
}

func GetSecretProviderClass(ctx context.Context, client client.Client, authentication *operatorv1.Authentication) (*csisecret.SecretProviderClass, error) {
	var secretName, _ = GetSecretNameAndRequiredFields(authentication)
	secretProviderClass := &csisecret.SecretProviderClass{}
	if err := client.Get(ctx, types.NamespacedName{Name: secretName, Namespace: common.OperatorNamespace()}, secretProviderClass); err != nil {
		if errors.IsNotFound(err) {
			log.Info("secret provider class not found, skipping")
			return nil, nil
		}
		return nil, err
	}
	return secretProviderClass, nil
}

func GetSecretNameAndRequiredFields(authentication *operatorv1.Authentication) (string, []string) {
	var secretName string
	var requiredFields []string
	if authentication.Spec.OIDC != nil {
		secretName = render.OIDCSecretName
		requiredFields = append(requiredFields, render.ClientIDSecretField, render.ClientSecretSecretField)
	} else if authentication.Spec.Openshift != nil {
		secretName = render.OpenshiftSecretName
		requiredFields = append(requiredFields, render.ClientIDSecretField, render.ClientSecretSecretField, render.RootCASecretField)
	} else if authentication.Spec.LDAP != nil {
		secretName = render.LDAPSecretName
		requiredFields = append(requiredFields, render.BindDNSecretField, render.BindPWSecretField, render.RootCASecretField)
	}
	return secretName, requiredFields
}

// GetIDPSecret retrieves the Secret containing sensitive information for the configuration IdP specified in the given
// operatorv1.Authentication CR.
func GetIDPSecret(ctx context.Context, client client.Client, authentication *operatorv1.Authentication) (*corev1.Secret, error) {
	var secretName, requiredFields = GetSecretNameAndRequiredFields(authentication)

	secret := &corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Name: secretName, Namespace: common.OperatorNamespace()}, secret); err != nil {
		return nil, fmt.Errorf("missing secret %s/%s: %w", common.OperatorNamespace(), secretName, err)
	}

	for _, field := range requiredFields {
		data := secret.Data[field]
		if len(data) == 0 {
			return nil, fmt.Errorf("%s is a required field for secret %s/%s", field, secret.Namespace, secret.Name)
		}
	}

	// Validate LDAP fields.
	bindDN := secret.Data[render.BindDNSecretField]
	bindPW := secret.Data[render.BindPWSecretField]
	if len(bindDN) > 0 && len(bindPW) > 0 {
		if _, err := ldap.ParseDN(string(bindDN)); err != nil {
			return nil, fmt.Errorf("secret %s/%s: should have a valid LDAP DN", common.OperatorNamespace(), secretName)
		}

		// When Dex starts, it uses os.ExpandEnv to set up its configuration inside a json formatted string. If we validate
		// the input in the operator, the user will catch the configuration issue sooner.
		const config = `{"bindDN": "$BIND_DN", "bindPW": "$BIND_PW"}`
		data := []byte(os.Expand(config, func(s string) string {
			return map[string]string{
				"BIND_DN": string(bindDN),
				"BIND_PW": string(bindPW),
			}[s]
		}))
		if err := json.Unmarshal(data, &map[string]any{}); err != nil {
			return nil, fmt.Errorf("fields bindDN and bindPW in secret %s/%s are not properly escaped", common.OperatorNamespace(), secretName)
		}
	}
	rootCA := secret.Data[render.RootCASecretField]
	if len(rootCA) > 0 {
		_, err := certificatemanagement.ParseCertificate(rootCA)
		if err != nil {
			return nil, fmt.Errorf("secret %s/%s should have a valid certificate for field rootCA", common.OperatorNamespace(), secretName)
		}
	}

	return secret, nil
}
