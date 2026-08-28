// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AuthMethod string

type EmailVerificationType string

const (
	EmailVerificationTypeVerify EmailVerificationType = "Verify"
	EmailVerificationTypeSkip   EmailVerificationType = "InsecureSkip"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=authentications,scope=Cluster

// Authentication is the Schema for the authentications API
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'tigera-secure'", message="resource name must be 'tigera-secure'"
type Authentication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthenticationSpec   `json:"spec,omitempty"`
	Status AuthenticationStatus `json:"status,omitempty"`
}

// AuthenticationSpec defines the desired state of Authentication
type AuthenticationSpec struct {
	// ManagerDomain is the domain name of the Manager
	// +required
	ManagerDomain string `json:"managerDomain,omitempty"`

	// If specified, UsernamePrefix is prepended to each user obtained from the identity provider. Note that
	// Kibana does not support a user prefix, so this prefix is removed from Kubernetes User when translating log access
	// ClusterRoleBindings into Elastic.
	// +optional
	UsernamePrefix string `json:"usernamePrefix,omitempty"`

	// If specified, GroupsPrefix is prepended to each group obtained from the identity provider. Note that
	// Kibana does not support a groups prefix, so this prefix is removed from Kubernetes Groups when translating log access
	// ClusterRoleBindings into Elastic.
	// +optional
	GroupsPrefix string `json:"groupsPrefix,omitempty"`

	// OIDC contains the configuration needed to setup OIDC authentication.
	// +optional
	OIDC *AuthenticationOIDC `json:"oidc,omitempty"`

	// Openshift contains the configuration needed to setup Openshift OAuth authentication.
	// +optional
	Openshift *AuthenticationOpenshift `json:"openshift,omitempty"`

	// LDAP contains the configuration needed to setup LDAP authentication.
	// +optional
	LDAP *AuthenticationLDAP `json:"ldap,omitempty"`

	// DexDeployment configures the Dex Deployment.
	// +optional
	DexDeployment *DexDeployment `json:"dexDeployment,omitempty"`
}

// AuthenticationStatus defines the observed state of Authentication
type AuthenticationStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AuthenticationOIDC is the configuration needed to setup OIDC.
type AuthenticationOIDC struct {
	// IssuerURL is the URL to the OIDC provider.
	// +required
	IssuerURL string `json:"issuerURL"`

	// UsernameClaim specifies which claim to use from the OIDC provider as the username.
	// +required
	UsernameClaim string `json:"usernameClaim"`

	// RequestedScopes is a list of scopes to request from the OIDC provider. If not provided, the following scopes are
	// requested: ["openid", "email", "profile", "groups", "offline_access"].
	// +optional
	RequestedScopes []string `json:"requestedScopes,omitempty"`

	// Deprecated. Please use Authentication.Spec.UsernamePrefix instead.
	// +optional
	UsernamePrefix string `json:"usernamePrefix,omitempty"`

	// GroupsClaim specifies which claim to use from the OIDC provider as the group.
	// +optional
	GroupsClaim string `json:"groupsClaim,omitempty"`

	// Deprecated. Please use Authentication.Spec.GroupsPrefix instead.
	// +optional
	GroupsPrefix string `json:"groupsPrefix,omitempty"`

	// Some providers do not include the claim "email_verified" when there is no verification in the user enrollment
	// process or if they are acting as a proxy for another identity provider. By default those tokens are deemed invalid.
	// To skip this check, set the value to "InsecureSkip".
	// Default: Verify
	// +optional
	// +kubebuilder:validation:Enum=Verify;InsecureSkip
	EmailVerification *EmailVerificationType `json:"emailVerification,omitempty"`

	// PromptTypes is an optional list of string values that specifies whether the identity provider prompts the end user
	// for re-authentication and consent. See the RFC for more information on prompt types:
	// https://openid.net/specs/openid-connect-core-1_0.html.
	// Default: "Consent"
	// +optional
	PromptTypes []PromptType `json:"promptTypes,omitempty"`

	// Default: "Dex"
	// +optional
	Type OIDCType `json:"type,omitempty"`
}

// OIDCType defines how OIDC is configured for Tigera Enterprise. Dex should be the best option for most use-cases.
// The Tigera option can help in specific use-cases, for instance, when you are unable to configure a client secret.
// One of: Dex, Tigera
// +kubebuilder:validation:Enum=Dex;Tigera
type OIDCType string

const (
	// OIDCTypeDex uses Dex IdP, a popular open-source tool for connecting OIDC.
	OIDCTypeDex OIDCType = "Dex"
	// OIDCTypeTigera uses customer code to pass OIDC configuration directly into our server applications.
	OIDCTypeTigera OIDCType = "Tigera"
)

// PromptType is a value that specifies whether the identity provider prompts the end user for re-authentication and
// consent.
// One of: None, Login, Consent, SelectAccount.
// +kubebuilder:validation:Enum=None;Login;Consent;SelectAccount
type PromptType string

const (
	// The identity provider must not display any authentication or consent user interface pages.
	PromptTypeNone PromptType = "None"
	// The identity provider should prompt the end user for reauthentication.
	PromptTypeLogin PromptType = "Login"
	// The identity provider should prompt the end user for consent before returning information to the client.
	PromptTypeConsent PromptType = "Consent"
	// The identity provider should prompt the end user to select a user account.
	PromptTypeSelectAccount PromptType = "SelectAccount"
)

// AuthenticationOpenshift is the configuration needed to setup Openshift.
type AuthenticationOpenshift struct {
	// IssuerURL is the URL to the Openshift OAuth provider. Ex.: https://api.my-ocp-domain.com:6443
	// +required
	IssuerURL string `json:"issuerURL"`
}

// AuthenticationLDAP is the configuration needed to setup LDAP.
type AuthenticationLDAP struct {
	// The host and port of the LDAP server. Example: ad.example.com:636
	// +required
	Host string `json:"host"`

	// StartTLS whether to enable the startTLS feature for establishing TLS on an existing LDAP session.
	// If true, the ldap:// protocol is used and then issues a StartTLS command, otherwise, connections will use
	// the ldaps:// protocol.
	// +optional
	StartTLS *bool `json:"startTLS,omitempty"`

	// User entry search configuration to match the credentials with a user.
	// +required
	UserSearch *UserSearch `json:"userSearch"`

	// Group search configuration to find the groups that a user is in.
	// +optional
	GroupSearch *GroupSearch `json:"groupSearch,omitempty"`
}

// User entry search configuration to match the credentials with a user.
type UserSearch struct {
	// BaseDN to start the search from. For example "cn=users,dc=example,dc=com"
	// +required
	BaseDN string `json:"baseDN"`

	// Optional filter to apply when searching the directory. For example "(objectClass=person)"
	// +optional
	Filter string `json:"filter,omitempty"`

	// A mapping of the attribute that is used as the username. This attribute can be used to apply RBAC to a user.
	// Default: uid
	// +optional
	NameAttribute string `json:"nameAttribute,omitempty"`
}

// Group search configuration to find the groups that a user is in.
type GroupSearch struct {
	// BaseDN to start the search from. For example "cn=groups,dc=example,dc=com"
	// +required
	BaseDN string `json:"baseDN"`

	// Optional filter to apply when searching the directory.
	// For example "(objectClass=posixGroup)"
	// +optional
	Filter string `json:"filter,omitempty"`

	// The attribute of the group that represents its name. This attribute can be used to apply RBAC to a user group.
	// +required
	NameAttribute string `json:"nameAttribute"`

	// Following list contains field pairs that are used to match a user to a group. It adds an additional
	// requirement to the filter that an attribute in the group must match the user's
	// attribute value.
	// +required
	UserMatchers []UserMatch `json:"userMatchers"`
}

// UserMatch when the value of a UserAttribute and a GroupAttribute match, a user belongs to the group.
type UserMatch struct {
	// The attribute of a user that links it to a group.
	// +required
	UserAttribute string `json:"userAttribute"`

	// The attribute of a group that links it to a user.
	// +required
	GroupAttribute string `json:"groupAttribute"`
}

// +kubebuilder:object:root=true

// AuthenticationList contains a list of Authentication
type AuthenticationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Authentication `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Authentication{}, &AuthenticationList{})
}
