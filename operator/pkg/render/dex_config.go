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
//

package render

import (
	"fmt"
	"strconv"
	"strings"

	csisecret "sigs.k8s.io/secrets-store-csi-driver/apis/v1"

	oprv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render/common/authentication"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	corev1 "k8s.io/api/core/v1"
)

const (
	// Types of dex connectors.
	connectorTypeOIDC      = "oidc"
	connectorTypeOpenshift = "openshift"
	connectorTypeGoogle    = "google"
	connectorTypeLDAP      = "ldap"

	// Various annotations to keep the pod up-to-date
	authenticationAnnotation = "hash.operator.tigera.io/tigera-dex-auth"
	dexConfigMapAnnotation   = "hash.operator.tigera.io/tigera-dex-config"
	dexIdpSecretAnnotation   = "hash.operator.tigera.io/tigera-idp-secret"

	// Constants related to secrets.
	serviceAccountSecretField    = "serviceAccountSecret"
	ClientSecretSecretField      = "clientSecret"
	adminEmailSecretField        = "adminEmail"
	serviceAccountFilePathField  = "serviceAccountFilePath"
	RootCASecretField            = "rootCA"
	OIDCSecretName               = "tigera-oidc-credentials"
	OIDCSecretProviderClassName  = "tigera-oidc-credentials"
	OpenshiftSecretName          = "tigera-openshift-credentials"
	LDAPSecretName               = "tigera-ldap-credentials"
	serviceAccountSecretLocation = "/etc/dex/secrets/google-groups.json"
	rootCASecretLocation         = "/etc/ssl/certs/idp.pem"
	ClientIDSecretField          = "clientID"
	BindDNSecretField            = "bindDN"
	BindPWSecretField            = "bindPW"

	// OIDC well-known-config related constants.
	jwksURI = "https://tigera-dex.tigera-dex.svc.%s:5556/dex/keys"

	// Env related constants.
	googleAdminEmailEnv = "ADMIN_EMAIL"
	clientIDEnv         = "CLIENT_ID"
	clientSecretEnv     = "CLIENT_SECRET"
	bindDNEnv           = "BIND_DN"
	bindPWEnv           = "BIND_PW"

	// Default claims to use to data from a JWT.
	DefaultGroupsClaim   = "groups"
	defaultUsernameClaim = "email"

	// Other constants
	googleIssuer = "https://accounts.google.com"
)

// DexConfig is a config for DexIdP itself.
type DexConfig interface {
	// Connector returns the dex connector configuration block.
	Connector() map[string]interface{}
	// RedirectURIs returns the list of redirect URIs for the dex static client.
	RedirectURIs() []string
	// Issuer returns the issuer URL for dex.
	Issuer() string
	// RequiredEnv returns env variables required by the dex deployment.
	RequiredEnv(prefix string) []corev1.EnvVar
	// RequiredAnnotations returns pod annotations required by the dex deployment.
	RequiredAnnotations() map[string]string
	// RequiredSecrets returns secrets required by the dex deployment in the given namespace.
	RequiredSecrets(namespace string) []*corev1.Secret
	// RequiredVolumeMounts returns volume mounts required by the dex deployment.
	RequiredVolumeMounts() []corev1.VolumeMount
	// RequiredVolumes returns volumes required by the dex deployment.
	RequiredVolumes() []corev1.Volume
	// RequiredSecretProviderClass returns SecretProviderClass objects required by the dex deployment.
	RequiredSecretProviderClass(namespace string) []*csisecret.SecretProviderClass
}

func NewDexKeyValidatorConfig(
	authentication *oprv1.Authentication,
	clusterDomain string) authentication.KeyValidatorConfig {
	// Compute baseURL similar to baseCfg but without creating dexBaseCfg.
	baseUrl := authentication.Spec.ManagerDomain
	if !strings.HasPrefix(baseUrl, "http://") && !strings.HasPrefix(baseUrl, "https://") {
		baseUrl = fmt.Sprintf("https://%s", baseUrl)
	}
	return &DexKeyValidatorConfig{
		authentication: authentication,
		baseURL:        baseUrl,
		clusterDomain:  clusterDomain,
	}
}

// Create a new DexConfig.
func NewDexConfig(
	certificateManagement *oprv1.CertificateManagement,
	authentication *oprv1.Authentication,
	idpSecret *corev1.Secret,
	secretProviderClass *csisecret.SecretProviderClass,
	clusterDomain string) DexConfig {
	return &dexConfig{
		dexBaseCfg:          baseCfg(certificateManagement, authentication, idpSecret, clusterDomain),
		secretProviderClass: secretProviderClass,
	}
}

type DexKeyValidatorConfig struct {
	authentication *oprv1.Authentication
	baseURL        string
	clusterDomain  string
	tlsSecret      certificatemanagement.KeyPairInterface
}

func (d *DexKeyValidatorConfig) BaseURL() string { return d.baseURL }

func (d *DexKeyValidatorConfig) Issuer() string { return fmt.Sprintf("%s/dex", d.baseURL) }

func (d *DexKeyValidatorConfig) ClientID() string { return DexClientId }

func (d *DexKeyValidatorConfig) UsernameClaim() string {
	claim := defaultUsernameClaim
	if d.authentication != nil && d.authentication.Spec.OIDC != nil && d.authentication.Spec.OIDC.UsernameClaim != "" {
		claim = d.authentication.Spec.OIDC.UsernameClaim
	}
	return claim
}

func (d *DexKeyValidatorConfig) RequiredConfigMaps(string) []*corev1.ConfigMap { return nil }

func (d *DexKeyValidatorConfig) RequiredVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{}
}

func (d *DexKeyValidatorConfig) RequiredVolumes() []corev1.Volume {
	return []corev1.Volume{}
}

type dexConfig struct {
	secretProviderClass *csisecret.SecretProviderClass
	*dexBaseCfg
}

// Create a struct to hold the base configuration of dex.
func baseCfg(
	certificateManagement *oprv1.CertificateManagement,
	authentication *oprv1.Authentication,
	idpSecret *corev1.Secret,
	clusterDomain string) *dexBaseCfg {

	// If the manager domain is not a URL, prepend https://.
	baseUrl := authentication.Spec.ManagerDomain
	if !strings.HasPrefix(baseUrl, "http://") && !strings.HasPrefix(baseUrl, "https://") {
		baseUrl = fmt.Sprintf("https://%s", baseUrl)
	}

	var connType string
	if authentication.Spec.OIDC != nil {
		if authentication.Spec.OIDC.IssuerURL == googleIssuer {
			connType = connectorTypeGoogle
		} else {
			connType = connectorTypeOIDC
		}
	} else if authentication.Spec.Openshift != nil {
		connType = connectorTypeOpenshift
	} else if authentication.Spec.LDAP != nil {
		connType = connectorTypeLDAP
	}

	return &dexBaseCfg{
		certificateManagement: certificateManagement,
		authentication:        authentication,
		idpSecret:             idpSecret,
		connectorType:         connType,
		baseURL:               baseUrl,
		clusterDomain:         clusterDomain,
	}
}

type dexBaseCfg struct {
	certificateManagement *oprv1.CertificateManagement
	authentication        *oprv1.Authentication
	tlsSecret             certificatemanagement.KeyPairInterface
	idpSecret             *corev1.Secret
	baseURL               string
	connectorType         string
	clusterDomain         string
}

func (d *dexBaseCfg) BaseURL() string {
	return d.baseURL
}

func (d *dexBaseCfg) Issuer() string {
	return fmt.Sprintf("%s/dex", d.baseURL)
}

func (d *dexBaseCfg) RedirectURIs() []string {
	redirectURIs := []string{
		// These call-back urls are used by the manager in order to obtain an access token.
		"https://localhost:9443/login/oidc/callback",
		"https://127.0.0.1:9443/login/oidc/callback",
		// These call-back urls are used by the manager in order to refresh the access tokens.
		"https://localhost:9443/login/oidc/silent-callback",
		"https://127.0.0.1:9443/login/oidc/silent-callback",
	}

	if d.baseURL != "" && !strings.Contains(d.baseURL, "localhost") && !strings.Contains(d.baseURL, "127.0.0.1") {
		redirectURIs = append(redirectURIs, fmt.Sprintf("%s/login/oidc/callback", d.baseURL))
		redirectURIs = append(redirectURIs, fmt.Sprintf("%s/login/oidc/silent-callback", d.baseURL))
	}

	return redirectURIs
}

func (d *dexBaseCfg) RequiredConfigMaps(string) []*corev1.ConfigMap {
	return nil
}

func (d *dexBaseCfg) ClientID() string {
	return DexClientId
}

func (d *dexBaseCfg) UsernameClaim() string {
	claim := defaultUsernameClaim
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.UsernameClaim != "" {
		claim = d.authentication.Spec.OIDC.UsernameClaim
	}
	return claim
}

func (d *dexBaseCfg) RequestedScopes() []string {
	if d.authentication.Spec.OIDC != nil && d.authentication.Spec.OIDC.RequestedScopes != nil {
		return d.authentication.Spec.OIDC.RequestedScopes
	}
	return []string{
		// openid: Standard OIDC scope, always required.
		"openid",
		// email: This is the one that requests the `email` and `email_verified` claims. It is the most commonly used username claim.
		"email",
		// profile: Gets user metadata claims like name, picture, etc.
		"profile",
		// offline_access: This claim is necessary for the PKCE flow in order to refresh access_tokens.
		"offline_access"}
}

func (d *dexBaseCfg) RequiredSecrets(namespace string) []*corev1.Secret {
	var secrets []*corev1.Secret
	if d.tlsSecret != nil {
		secrets = append(secrets, d.tlsSecret.Secret(namespace))
	}
	if d.idpSecret != nil {
		secrets = append(secrets, secret.CopyToNamespace(namespace, d.idpSecret)...)
	}
	return secrets
}

func (d *dexConfig) RequiredSecretProviderClass(namespace string) []*csisecret.SecretProviderClass {
	var secrets []*csisecret.SecretProviderClass
	if d.secretProviderClass != nil {
		secrets = append(secrets, secret.CopySecretProviderClassToNamespace(namespace, d.secretProviderClass)...)
	}
	return secrets
}

// RequiredAnnotations returns the annotations that are relevant for a Dex deployment.
func (d *dexConfig) RequiredAnnotations() map[string]string {
	var annotations = map[string]string{
		dexConfigMapAnnotation: rmeta.AnnotationHash(d.Connector()),
	}

	if d.tlsSecret != nil {
		annotations[d.tlsSecret.HashAnnotationKey()] = d.tlsSecret.HashAnnotationValue()
	}

	if d.idpSecret != nil {
		annotations[dexIdpSecretAnnotation] = rmeta.AnnotationHash(d.idpSecret.Data)
	}
	return annotations
}

func (d *DexKeyValidatorConfig) RequiredSecrets(namespace string) []*corev1.Secret {
	var secrets []*corev1.Secret
	if d.tlsSecret != nil {
		secrets = append(secrets, d.tlsSecret.Secret(namespace))
	}
	return secrets
}

// RequiredAnnotations returns the annotations that are relevant for a validator config.
func (d *DexKeyValidatorConfig) RequiredAnnotations() map[string]string {
	var annotations = map[string]string{
		authenticationAnnotation: rmeta.AnnotationHash([]interface{}{d.UsernameClaim(), d.BaseURL()}),
	}
	return annotations
}

// Append variables that are necessary for using the dex authenticator.
func (d *DexKeyValidatorConfig) RequiredEnv(prefix string) []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: fmt.Sprintf("%sDEX_ENABLED", prefix), Value: strconv.FormatBool(true)},
		{Name: fmt.Sprintf("%sDEX_URL", prefix), Value: fmt.Sprintf("https://tigera-dex.tigera-dex.svc.%s:5556/", d.clusterDomain)},
		{Name: fmt.Sprintf("%sOIDC_AUTH_ENABLED", prefix), Value: strconv.FormatBool(true)},
		{Name: fmt.Sprintf("%sOIDC_AUTH_ISSUER", prefix), Value: fmt.Sprintf("%s/dex", d.BaseURL())},
		{Name: fmt.Sprintf("%sOIDC_AUTH_JWKSURL", prefix), Value: fmt.Sprintf(jwksURI, d.clusterDomain)},
		{Name: fmt.Sprintf("%sOIDC_AUTH_CLIENT_ID", prefix), Value: DexClientId},
		{Name: fmt.Sprintf("%sOIDC_AUTH_USERNAME_CLAIM", prefix), Value: d.UsernameClaim()},
		{Name: fmt.Sprintf("%sOIDC_AUTH_GROUPS_CLAIM", prefix), Value: DefaultGroupsClaim},
		{Name: fmt.Sprintf("%sOIDC_AUTH_USERNAME_PREFIX", prefix), Value: d.authentication.Spec.UsernamePrefix},
		{Name: fmt.Sprintf("%sOIDC_AUTH_GROUPS_PREFIX", prefix), Value: d.authentication.Spec.GroupsPrefix},
	}
}

// Append variables that are necessary for configuring dex.
func (d *dexConfig) RequiredEnv(string) []corev1.EnvVar {
	var env []corev1.EnvVar
	if d.idpSecret != nil {
		addIfPresent := func(fieldName, envName string) {
			if _, found := d.idpSecret.Data[fieldName]; found {
				env = append(env, corev1.EnvVar{Name: envName, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: fieldName, LocalObjectReference: corev1.LocalObjectReference{Name: d.idpSecret.Name}}}})
			}
		}
		addIfPresent(ClientIDSecretField, clientIDEnv)
		addIfPresent(ClientSecretSecretField, clientSecretEnv)
		addIfPresent(adminEmailSecretField, googleAdminEmailEnv)
		addIfPresent(BindDNSecretField, bindDNEnv)
		addIfPresent(BindPWSecretField, bindPWEnv)
	}

	return env
}

func (d *dexConfig) RequiredVolumes() []corev1.Volume {
	defaultMode := int32(420)
	volumes := []corev1.Volume{
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: DexObjectName}, Items: []corev1.KeyToPath{{Key: "config.yaml", Path: "config.yaml"}}}},
		},
	}

	var secretItems []corev1.KeyToPath
	if d.idpSecret != nil && d.idpSecret.Data[serviceAccountSecretField] != nil {
		secretItems = append(secretItems, corev1.KeyToPath{Key: serviceAccountSecretField, Path: "google-groups.json"})
	}
	if d.idpSecret != nil && d.idpSecret.Data[RootCASecretField] != nil {
		secretItems = append(secretItems, corev1.KeyToPath{Key: RootCASecretField, Path: "idp.pem"})
	}
	if len(secretItems) > 0 {
		volumes = append(volumes,
			corev1.Volume{
				Name:         "secrets",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{DefaultMode: &defaultMode, SecretName: d.idpSecret.Name, Items: secretItems}},
			},
		)
	}

	if d.secretProviderClass != nil {
		isReadOnly := true
		volumes = append(volumes,
			corev1.Volume{
				Name: "secrets-store",
				VolumeSource: corev1.VolumeSource{
					CSI: &corev1.CSIVolumeSource{
						Driver:   "secrets-store.csi.k8s.io",
						ReadOnly: &isReadOnly,
						VolumeAttributes: map[string]string{
							"secretProviderClass": d.secretProviderClass.Name,
						},
					},
				},
			},
		)
	}
	return volumes
}

// AppendDexVolumeMount adds mount for ubi base image trusted cert location
func (d *dexConfig) RequiredVolumeMounts() []corev1.VolumeMount {
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      "config",
			MountPath: "/etc/dex/baseCfg",
			ReadOnly:  true,
		},
	}
	if d.idpSecret != nil && d.idpSecret.Data[serviceAccountSecretField] != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "secrets",
			MountPath: "/etc/dex/secrets",
			ReadOnly:  true,
		})
	}
	if d.idpSecret != nil && d.idpSecret.Data[RootCASecretField] != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "secrets",
			MountPath: "/etc/ssl/certs/",
			ReadOnly:  true,
		})
	}

	if d.secretProviderClass != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "secrets-store",
			MountPath: "/mnt/secrets-store",
			ReadOnly:  true,
		})
	}
	return volumeMounts
}

// This func prepares the configuration and objects that will be rendered related to the connector and its secrets.
func (d *dexConfig) Connector() map[string]interface{} {
	var config map[string]interface{}
	connectorType := d.connectorType

	switch connectorType {
	case connectorTypeOIDC:
		config = map[string]interface{}{
			"issuer":       d.authentication.Spec.OIDC.IssuerURL,
			"clientID":     fmt.Sprintf("$%s", clientIDEnv),
			"clientSecret": fmt.Sprintf("$%s", clientSecretEnv),
			"redirectURI":  fmt.Sprintf("%s/dex/callback", d.BaseURL()),
			"scopes":       d.RequestedScopes(),
			"userNameKey":  d.UsernameClaim(),
			"userIDKey":    d.UsernameClaim(),
			"insecureSkipEmailVerified": d.authentication.Spec.OIDC.EmailVerification != nil &&
				*d.authentication.Spec.OIDC.EmailVerification == oprv1.EmailVerificationTypeSkip,
			// Although the field is called insecure, it no longer is. It was first introduced without proper refreshing
			// of the groups claim, leading to stale groups. This has been addressed in Dex v2.25, yet the field retains
			// this name.
			"insecureEnableGroups": true,
		}
		promptTypes := d.authentication.Spec.OIDC.PromptTypes
		if promptTypes != nil {
			length := len(promptTypes)
			prompts := make([]string, length)
			for i, v := range promptTypes {
				switch v {
				case oprv1.PromptTypeNone:
					prompts[i] = "none"
				case oprv1.PromptTypeSelectAccount:
					prompts[i] = "select_account"
				case oprv1.PromptTypeLogin:
					prompts[i] = "login"
				case oprv1.PromptTypeConsent:
					prompts[i] = "consent"
				}
			}
			// RFC specifies space delimited case sensitive list: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			config["promptType"] = strings.Join(prompts, " ")
		}
		groupsClaim := d.authentication.Spec.OIDC.GroupsClaim
		if groupsClaim != "" && groupsClaim != DefaultGroupsClaim {
			config["claimMapping"] = map[string]string{
				"groups": groupsClaim,
			}
		}

	case connectorTypeGoogle:
		config = map[string]interface{}{
			"issuer":       googleIssuer,
			"clientID":     fmt.Sprintf("$%s", clientIDEnv),
			"clientSecret": fmt.Sprintf("$%s", clientSecretEnv),
			"redirectURI":  fmt.Sprintf("%s/dex/callback", d.BaseURL()),
			"scopes":       d.RequestedScopes(),
			"insecureSkipEmailVerified": d.authentication.Spec.OIDC.EmailVerification != nil &&
				*d.authentication.Spec.OIDC.EmailVerification == oprv1.EmailVerificationTypeSkip,
		}
		if d.idpSecret != nil && d.idpSecret.Data[serviceAccountSecretField] != nil && d.idpSecret.Data[adminEmailSecretField] != nil {
			config[serviceAccountFilePathField] = serviceAccountSecretLocation
			config[adminEmailSecretField] = fmt.Sprintf("$%s", googleAdminEmailEnv)
		}

	case connectorTypeOpenshift:
		config = map[string]interface{}{
			"issuer":          d.authentication.Spec.Openshift.IssuerURL,
			"clientID":        fmt.Sprintf("$%s", clientIDEnv),
			"clientSecret":    fmt.Sprintf("$%s", clientSecretEnv),
			"redirectURI":     fmt.Sprintf("%s/dex/callback", d.BaseURL()),
			RootCASecretField: rootCASecretLocation,
		}
	case connectorTypeLDAP:
		config = map[string]interface{}{
			"host":            d.authentication.Spec.LDAP.Host,
			"bindDN":          fmt.Sprintf("$%s", bindDNEnv),
			"bindPW":          fmt.Sprintf("$%s", bindPWEnv),
			"startTLS":        d.authentication.Spec.LDAP.StartTLS != nil && *d.authentication.Spec.LDAP.StartTLS,
			RootCASecretField: rootCASecretLocation,
			"userSearch": map[string]string{
				"baseDN":    d.authentication.Spec.LDAP.UserSearch.BaseDN,
				"filter":    d.authentication.Spec.LDAP.UserSearch.Filter,
				"emailAttr": d.authentication.Spec.LDAP.UserSearch.NameAttribute,
				"idAttr":    d.authentication.Spec.LDAP.UserSearch.NameAttribute,
				"username":  d.authentication.Spec.LDAP.UserSearch.NameAttribute,
				"nameAttr":  d.authentication.Spec.LDAP.UserSearch.NameAttribute,
			},
		}
		if d.authentication.Spec.LDAP.GroupSearch != nil {
			matchers := make([]map[string]string, len(d.authentication.Spec.LDAP.GroupSearch.UserMatchers))
			for i, match := range d.authentication.Spec.LDAP.GroupSearch.UserMatchers {
				matchers[i] = map[string]string{
					"userAttr":  match.UserAttribute,
					"groupAttr": match.GroupAttribute,
				}
			}

			config["groupSearch"] = map[string]interface{}{
				"baseDN":       d.authentication.Spec.LDAP.GroupSearch.BaseDN,
				"filter":       d.authentication.Spec.LDAP.GroupSearch.Filter,
				"nameAttr":     d.authentication.Spec.LDAP.GroupSearch.NameAttribute,
				"userMatchers": matchers,
			}
		}
	default:

	}

	return map[string]interface{}{
		"id":     connectorType,
		"type":   connectorType,
		"name":   connectorType,
		"config": config,
	}
}
