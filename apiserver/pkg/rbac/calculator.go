// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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

package rbac

import (
	"fmt"
	"strings"
	"sync"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbac_auth "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
)

// Verb is a bit-wise set of available verbs for Kubernetes RBAC. Use Verbs() to convert to a slice of strings.
type Verb string

const (
	VerbGet    Verb = "get"
	VerbList   Verb = "list"
	VerbUpdate Verb = "update"
	VerbCreate Verb = "create"
	VerbPatch  Verb = "patch"
	VerbDelete Verb = "delete"
	VerbWatch  Verb = "watch"
)

const (
	resourceTiers                       = "tiers"
	resourceNamespaces                  = "namespaces"
	resourceNetworkPolicies             = "networkpolicies"
	resourceGlobalNetworkPolicies       = "globalnetworkpolicies"
	resourceStageNetworkPolicies        = "stagednetworkpolicies"
	resourceStagedGlobalNetworkPolicies = "stagedglobalnetworkpolicies"
)

var AllVerbs = []Verb{
	VerbGet, VerbList, VerbUpdate, VerbCreate, VerbPatch, VerbDelete, VerbWatch,
}

// Calculator provides methods to determine RBAC permissions for a user.
type Calculator interface {
	CalculatePermissions(user user.Info, rvs []ResourceVerbs) (Permissions, error)
}

// Permissions contains the calculated set of permissions for a single request. This organizes by resource type and
// then verb.  The set of matches consists of the authorized namespaces and tiers for a particular resource type and
// verb pairing.
//
// If the match slice is nil or empty then the user is not authorized to perform the action at a namespace level or
// cluster-wide.
//
// If the user is authorized cluster-wide, the namespace field in the Match entry will be an empty string. This applies
// to both namespaced and cluster-scoped resource types.
type Permissions map[ResourceType]map[Verb][]Match

// ResourceType encapsulates the APIGroup and Resource.  The Resource is the lowercase plural kind used in the RBAC
// configuration (e.g. pods).
type ResourceType struct {
	APIGroup string
	Resource string
}

// ResourceVerbs encapsulates a resource type with a set of verbs. This is used in the request. The response orders the
// data slightly differently to handle de-duplication.
type ResourceVerbs struct {
	ResourceType ResourceType
	Verbs        []Verb
}

func (rt ResourceType) MarshalText() ([]byte, error) {
	return []byte(rt.String()), nil
}

func (rt *ResourceType) UnmarshalText(b []byte) error {
	parts := strings.SplitN(string(b), ".", 2)
	rt.Resource = parts[0]
	if len(parts) == 2 {
		rt.APIGroup = parts[1]
	}
	return nil
}

func (r ResourceType) String() string {
	if r.APIGroup == "" {
		return r.Resource
	}
	return r.Resource + "." + r.APIGroup
}

// Match contains details of a set of RBAC authorization matches for given ResourceType/Verb combination.  An empty
// string indicates a wildcard match.
type Match struct {
	// A blank namespace indicates a cluster-wide match. This is applicable to namespaced and cluster-scoped resource
	// types.
	//
	// For Namespace queries, the Namespace field will never be wildcarded for the "get" verb, it may be wildcarded or
	// explicit for "watch", and is only ever wildcarded for remaining verbs (e.g. the RBAC calculator never expands down
	// to individual namespaces for "create", "delete" etc.)
	Namespace string `json:"namespace"`

	// Tier will never be wildcarded for Calico tiered policies, i.e. the response will contain explicit
	// match entries for each authorized tier.
	//
	// For Tier queries, the Tier field will never be wildcarded for the "get" verb, it may be wildcarded or explicit for
	// "watch", and is only ever wildcarded for remaining verbs (e.g. the RBAC calculator never expands down to individual
	// tiers for "create", "delete" etc.)
	Tier string `json:"tier"`
}

func (m Match) String() string {
	return fmt.Sprintf("Match(tier=%s; namespace=%s)", m.Tier, m.Namespace)
}

// NewCalculator creates a new RBAC Calculator.
func NewCalculator(
	resourceLister ResourceLister,
	clusterRoleGetter ClusterRoleGetter,
	clusterRoleBindingLister ClusterRoleBindingLister,
	roleGetter RoleGetter,
	roleBindingLister RoleBindingLister,
	namespaceLister NamespaceLister,
	calicoResourceLister CalicoResourceLister,
	minResourceRefreshInterval time.Duration,
) Calculator {
	// Split out the cluster and namespaced rule resolvers - this allows us to perform namespace queries without
	// checking cluster rules every time. For cluster specific rule resolver, use a "no-op" RuleBindingLister - this
	// is a lister that returns no RuleBindings, the upshot is that only ClusterRoleBindings are discovered by the
	// RuleResolver meaning only cluster-scoped rules will be considered.  Similarly,for the namespaced rule resolver,
	// use a no-op ClusterRoleBindingLister - this is a lister that returns no ClusterRoleBindings and so the
	// RuleResolver will only discover namespaced rules (and no cluster-scoped rules).
	clusterRuleResolver := validation.NewDefaultRuleResolver(
		roleGetter, &emptyK8sRoleBindingLister{}, clusterRoleGetter, clusterRoleBindingLister,
	)
	namespacedRuleResolver := validation.NewDefaultRuleResolver(
		roleGetter, roleBindingLister, clusterRoleGetter, &emptyK8sClusterRoleBindingLister{},
	)

	return &calculator{
		resourceLister:             resourceLister,
		namespaceLister:            namespaceLister,
		calicoResourceLister:       calicoResourceLister,
		clusterRuleResolver:        clusterRuleResolver,
		namespacedRuleResolver:     namespacedRuleResolver,
		minResourceRefreshInterval: minResourceRefreshInterval,
	}
}

// RoleGetter interface is used to get a specific Role.
type RoleGetter interface {
	GetRole(namespace, name string) (*rbacv1.Role, error)
}

// RoleBindingLister interface is used to list all RoleBindings in a specific namespace.
type RoleBindingLister interface {
	ListRoleBindings(namespace string) ([]*rbacv1.RoleBinding, error)
}

// ClusterRoleGetter interface is used to get a specific ClusterRole.
type ClusterRoleGetter interface {
	GetClusterRole(name string) (*rbacv1.ClusterRole, error)
}

// ClusterRoleBindingLister interface is used to list all ClusterRoleBindings.
type ClusterRoleBindingLister interface {
	ListClusterRoleBindings() ([]*rbacv1.ClusterRoleBinding, error)
}

// NamespaceLister interface is used to list all Namespaces.
type NamespaceLister interface {
	ListNamespaces() ([]*corev1.Namespace, error)
}

// CalicoResourceLister interface is used to list the required Calico resource types.
type CalicoResourceLister interface {
	ListTiers() ([]*v3.Tier, error)
}

// ResourceLister interface is used to list registered resource types.
type ResourceLister interface {
	ServerPreferredResources() ([]*metav1.APIResourceList, error)
}

// apiResource encapsulates key data about a resource type extracted from the server preferred resource query.
type apiResource struct {
	ResourceType
	Namespaced bool
}

// isNamespace returns true if the apiResource represents a Kubernetes Namespace.
func (ar apiResource) isNamespace() bool {
	if ar.APIGroup != "" {
		return false
	}
	return ar.Resource == resourceNamespaces
}

// isTier returns true if the apiResource represents a Calico Tier.
func (ar apiResource) isTier() bool {
	if ar.APIGroup != v3.Group {
		return false
	}
	return ar.Resource == resourceTiers
}

// isTieredPolicy returns true is the apiResource represents a Calico tiered network policy.
func (ar apiResource) isTieredPolicy() bool {
	if ar.APIGroup != v3.Group {
		return false
	}
	switch ar.Resource {
	case resourceNetworkPolicies,
		resourceGlobalNetworkPolicies,
		resourceStageNetworkPolicies,
		resourceStagedGlobalNetworkPolicies:
		return true
	}
	return false
}

// rbacResource returns the resource type actually used to calculate the users RBAC.
func (ar apiResource) rbacResource() (resource string, subresource string) {
	if ar.isTieredPolicy() {
		// for Calico tiered policies we use a special "tier.xxx" format to allow special case processing for fine grained
		// access control at the tier level
		return "tier." + ar.Resource, ""
	}
	// For all other resources this is simply the resource plural form unchanged
	return ar.Resource, ""
}

// calculator implements the Calculator interface.
//
// this struct mainly serves as a cached resource store and defers implementation of the Calculator interface
// to the userCalculator.
type calculator struct {
	resourceLister         ResourceLister
	namespaceLister        NamespaceLister
	calicoResourceLister   CalicoResourceLister
	clusterRuleResolver    validation.AuthorizationRuleResolver
	namespacedRuleResolver validation.AuthorizationRuleResolver

	// This is determined at most once per request, and only in the event the request contains an unknown resource type.
	// Once a resource type is known, the properties associated with that resource type are not expected to change.
	minResourceRefreshInterval time.Duration

	// resources is the set of cached resources.
	resources          map[ResourceType]apiResource
	resourceUpdateTime time.Time
	resourceLock       sync.Mutex
}

// CalculatePermissions calculates the RBAC permissions for a specific user and set of resource types.
func (c *calculator) CalculatePermissions(user user.Info, rvs []ResourceVerbs) (Permissions, error) {
	log.Debugf("CalculatePermissions for %v using %#v", user, rvs)

	// Get the resource information - this will initialise our resource types if not already initialized.
	resources, resourceUpdateTime, err := c.getResourceInfo()
	if err != nil {
		return nil, err
	}

	// Create a new user calculator using the current set of resources and return the authorized verbs for the user and any errors that were hit.
	// This may result in an update to the cached resource types if the calculcator does not know about a requested resource type.
	return newUserCalculator(c, user, resources, resourceUpdateTime).Calculate(rvs)
}

// getResourceInfo returns the current registered resource cache and loads from API if it has not yet been initialized.
func (c *calculator) getResourceInfo() (map[ResourceType]apiResource, time.Time, error) {
	c.resourceLock.Lock()
	defer c.resourceLock.Unlock()
	if c.resources == nil {
		if err := c.loadResources(); err != nil {
			return nil, time.Time{}, err
		}
	}
	return c.resources, c.resourceUpdateTime, nil
}

// loadResources loads the registered resources from the k8s API server and caches the result. The resourceLock should
// be held by the caller.
func (c *calculator) loadResources() error {
	// Check we did not refresh recently. If we did, do nothing.
	if time.Since(c.resourceUpdateTime) < c.minResourceRefreshInterval {
		log.Debug("Resources were refreshed recently, not refreshing this time")
		return nil
	}

	// Get the registered resource groups and types.
	log.Debug("Querying k8s for registered resource types")
	pr, err := c.resourceLister.ServerPreferredResources()
	if err != nil {
		return err
	}

	resources := make(map[ResourceType]apiResource)
	for _, l := range pr {
		gv, err := schema.ParseGroupVersion(l.GroupVersion)
		if err != nil {
			log.WithError(err).Warnf("Unable to parse group version: %s", l.GroupVersion)
			continue
		}

		for _, rr := range l.APIResources {
			rt := ResourceType{APIGroup: gv.Group, Resource: rr.Name}
			resources[rt] = apiResource{ResourceType: rt, Namespaced: rr.Namespaced}
		}
	}

	// Store the resources and increment the revision number. The revision is used to determine if new resources were
	// loaded mid-query as the result of a concurrent request.
	log.Debugf("Loaded resources: %#v", resources)
	c.resources = resources
	c.resourceUpdateTime = time.Now()
	return nil
}

// emptyK8sRoleBindingLister implements the RoleBindingLister interface returning no RoleBindings.
type emptyK8sRoleBindingLister struct{}

func (_ *emptyK8sRoleBindingLister) ListRoleBindings(namespace string) ([]*rbacv1.RoleBinding, error) {
	return nil, nil
}

// emptyK8sClusterRoleBindingLister implements the ClusterRoleBindingLister interface returning no ClusterRoleBindings.
type emptyK8sClusterRoleBindingLister struct{}

func (_ *emptyK8sClusterRoleBindingLister) ListClusterRoleBindings() ([]*rbacv1.ClusterRoleBinding, error) {
	return nil, nil
}

// userCalculator is used to gather user specific Calculator permissions.
type userCalculator struct {
	resources              map[ResourceType]apiResource
	resourcesUpdated       bool
	resourcesUpdateTime    time.Time
	user                   user.Info
	errors                 []error
	calculator             *calculator
	allTiers               []types.NamespacedName
	gettableTiers          []types.NamespacedName
	allNamespaces          []types.NamespacedName
	gettableNamespaces     []types.NamespacedName
	clusterRules           []rbacv1.PolicyRule
	namespacedRules        map[string][]rbacv1.PolicyRule
	canGetAllTiersVal      *bool
	canGetAllNamespacesVal *bool
	permissions            Permissions
}

// newUserCalculator returns a new Calculator accumulator. This is used to gather user specific Calculator permissions.
func newUserCalculator(c *calculator, user user.Info, resources map[ResourceType]apiResource, resourceUpdateTime time.Time) *userCalculator {
	return &userCalculator{
		resources:           resources,
		resourcesUpdateTime: resourceUpdateTime,
		user:                user,
		calculator:          c,
		permissions:         make(Permissions),
	}
}

// getMatches returns the calculated matches for a specific resource and verb.
func (u *userCalculator) getMatches(verb Verb, res apiResource, subresource string) []Match {
	var matches []Match
	var match Match
	resource, reqdSubresource := res.rbacResource()

	// User should not be requesting a subresource when a subresource is already used for the resource RBAC.
	if subresource != "" && reqdSubresource != "" {
		log.Debugf("Requested subresource and required subresource are both non-zero: %s and %s", subresource, reqdSubresource)
		return nil
	}
	if reqdSubresource != "" {
		// If the RBAC is determined by a required sub resource, then use that when querying the RBAC.
		subresource = reqdSubresource
	}

	record := authorizer.AttributesRecord{
		Verb:            string(verb),
		APIGroup:        res.APIGroup,
		Resource:        resource,
		Subresource:     subresource,
		Name:            "",
		ResourceRequest: true,
	}
	log.Debugf("getMatches: %s %#v", verb, record)

	// In general we only look for user authorization at the namespace and cluster scoped level. However, there are
	// some important deviations that are specific to providing a good user experience with the Tigera UI.
	//
	// - "get" queries for namespaces, tiers, and managedclusters are always expanded out by name, even if the user has cluster-scoped
	//   get access for that resource. This is to allow RBAC controls being set to not permit "list" access, but provide
	//   a way for the UI to determine the limited subset of tiers and namespaces the user is allowed to see.
	//   We may wish to expand this to include other resource types too - especially anywhere the UI provides
	//   field selections refering to another resource.
	// - "watch" queries for namespaces, tiers, and managedclusters will be expanded out by name iff the user does not have cluster-scoped
	//   watch access.
	// - Any action for tiered policies is expanded across the "gettable" tiers. The RBAC calculator never wildcards the
	//   tier value for a tiered policy verb.

	if verb == VerbGet {
		if res.isTier() {
			// Special case tier gets - we always expand get across Tiers, so include all configured Tiers.
			log.Debug("Return gettable Tiers")
			for _, tier := range u.getGettableTiers() {
				match.Tier = tier.Name
				matches = append(matches, match)
			}

			return matches
		} else if res.isNamespace() {
			// Special case namespace gets - we always expand get across Namespaces, so include all configured Namespaces.
			log.Debug("Return gettable Namespaces")
			for _, namespace := range u.getGettableNamespaces() {
				match.Namespace = namespace.Name
				matches = append(matches, match)
			}

			return matches
		}
	}

	// Check if this resource is allowed cluster-wide with full wildcarded name. If it is then:
	if rbac_auth.RulesAllow(record, u.getClusterRules()...) {
		log.Debug("Full wildcard match")

		if res.isTieredPolicy() {
			// This is a tiered policy, expand the results by gettable tier.
			for _, tier := range u.getGettableTiers() {
				log.Debugf("Add cluster match for tiered-policy: tier=%s", tier)
				match.Tier = tier.Name
				matches = append(matches, match)
			}
		} else {
			// This is not a tiered policy so include the match unchanged.
			log.Debug("Add cluster match for non-tiered policy")
			matches = append(matches, match)
		}

		return matches
	}

	if verb == VerbWatch {
		// If not allowed cluster-wide with full wildcarded-name, then expand watch for tier, namespace and uisettings.
		if res.isTier() {
			log.Debug("Return individual watchable Tiers")
			tiers := u.expandResourceByName(u.getAllTiers(), verb, res)
			for _, tier := range tiers {
				match.Tier = tier.Name
				matches = append(matches, match)
			}
			// Nothing else to do for this resource.
			return matches
		} else if res.isNamespace() {
			log.Debug("Return individual watchable Namespaces")
			namespaces := u.expandResourceByName(u.getAllNamespaces(), verb, res)
			for _, namespace := range namespaces {
				match.Namespace = namespace.Name
				matches = append(matches, match)
			}
			// Nothing else to do for this resource.
			return matches
		}
	}

	// If we are processing a tiered policy, check if the user has cluster-scoped access within the tier. We check this
	// by using a resource name of <tier-name>.*
	//
	// Note that if we do not have cluster-wide access for the tier then we'll need to check per-namespace, so we track
	// Tiers that did not match cluster scoped.
	var tiersNoClusterMatch []string
	if res.isTieredPolicy() {
		log.Debug("Check cluster-scoped tiered-policy in each gettable tier")

		for _, tier := range u.getGettableTiers() {
			record.Name = tier.Name + ".*"
			if rbac_auth.RulesAllow(record, u.getClusterRules()...) {
				log.Debugf("Rules allow cluster-scoped policy in tier(%s)", tier)
				match.Tier = tier.Name
				matches = append(matches, match)
			} else {
				log.Debugf("Rules do not allow cluster-scoped policy in tier(%s)", tier)
				tiersNoClusterMatch = append(tiersNoClusterMatch, tier.Name)
			}
		}

		if tiersNoClusterMatch == nil {
			// If every tier was specified individually and matched cluster-wide, then there is no point in checking
			// per-namespace.
			log.Debug("All Tiers individually matched cluster-wide")
			return matches
		}
	}

	// If the resource is not namespaced then no more checks.
	if !res.Namespaced {
		log.Debug("Resource is not namespaced, so nothing left to check")
		return matches
	}

	// Now check namespaced matches. We limit this just to the Namespaces that the user has rules for.
	for namespace, rules := range u.getNamespacedRules() {
		log.Debugf("Processing rules for namespace %s", namespace)
		match.Namespace = namespace
		match.Tier = ""
		record.Namespace = namespace
		record.Name = ""
		if rbac_auth.RulesAllow(record, rules...) {
			// The user is authorized for full wildcarded names for the resource type in this namespace
			// -  If this is a tiered policy then expand by tier.
			// -  Otherwise, include a single wildcarded name result.
			if !res.isTieredPolicy() {
				// This is not a tiered policy so include the match unchanged.
				log.Debug("Add namespaced match for non-tiered policy")
				matches = append(matches, match)
			} else {
				// This is a tiered policy, expand the results by gettable tier.
				log.Debug("Add namespaced match for all Tiers for tiered policy")
				for _, tier := range tiersNoClusterMatch {
					log.Debugf("Add namespaced match for tiered policy: tier=%s", tier)
					match.Tier = tier
					matches = append(matches, match)
				}
			}

			// We matched wildcard name, so go to next namespace.
			continue
		}

		// Did not match wildcarded tier, so try individual Tiers (that were not matched cluster-wide).
		// [note: tiersNoClusterMatch will be nil if this is not a tiered policy resource]
		for _, tier := range tiersNoClusterMatch {
			record.Name = tier + ".*"
			if rbac_auth.RulesAllow(record, rules...) {
				log.Debugf("Add namespaced match for tiered policy: tier=%s", tier)
				match.Tier = tier
				matches = append(matches, match)
			}
		}
	}

	return matches
}

// canGetAllTiers determines whether the user is able to get all Tiers.
func (u *userCalculator) canGetAllTiers() bool {
	if u.canGetAllTiersVal == nil {
		allTiers := rbac_auth.RulesAllow(authorizer.AttributesRecord{
			Verb:            string(VerbGet),
			APIGroup:        v3.Group,
			Resource:        resourceTiers,
			Name:            "",
			ResourceRequest: true,
		}, u.getClusterRules()...)
		u.canGetAllTiersVal = &allTiers
	}

	return *u.canGetAllTiersVal
}

// getAllTiers returns the current set of configured Tiers.
func (u *userCalculator) getAllTiers() []types.NamespacedName {
	if u.allTiers == nil {
		if tiers, err := u.calculator.calicoResourceLister.ListTiers(); err != nil {
			log.WithError(err).Debug("Failed to list Tiers")
			u.errors = append(u.errors, err)
			u.allTiers = make([]types.NamespacedName, 0)
		} else {
			for _, tier := range tiers {
				u.allTiers = append(u.allTiers, types.NamespacedName{Name: tier.Name})
			}
		}
		log.Debugf("getAllTiers returns %v", u.allTiers)
	}
	return u.allTiers
}

// getGettableTiers determines which Tiers the user is able to get.
func (u *userCalculator) getGettableTiers() []types.NamespacedName {
	if u.gettableTiers == nil {
		for _, tier := range u.getAllTiers() {
			if u.canGetAllTiers() || rbac_auth.RulesAllow(authorizer.AttributesRecord{
				Verb:            string(VerbGet),
				APIGroup:        v3.Group,
				Resource:        resourceTiers,
				Name:            tier.Name,
				ResourceRequest: true,
			}, u.getClusterRules()...) {
				u.gettableTiers = append(u.gettableTiers, tier)
			}
		}
		log.Debugf("getGettableTiers returns %v", u.gettableTiers)
	}

	return u.gettableTiers
}

// expandResourceByName checks authorization of a verb on a specific resource type for individual
// names. This is only used in certain cases because expanding by name could be an expensive operation.
func (u *userCalculator) expandResourceByName(names []types.NamespacedName, verb Verb, res apiResource) (rs []types.NamespacedName) {
	for _, name := range names {
		log.Debugf("check RBAC for resource %v", name)
		rules := u.getClusterRules()
		if name.Namespace != "" {
			log.Debugf("Include namespace rules for %v", name)
			rules = append(rules, u.getNamespacedRules()[name.Namespace]...)
		}
		if rbac_auth.RulesAllow(authorizer.AttributesRecord{
			Verb:            string(verb),
			APIGroup:        res.APIGroup,
			Resource:        res.Resource,
			Name:            name.Name,
			Namespace:       name.Namespace,
			ResourceRequest: true,
		}, rules...) {
			rs = append(rs, name)
		}

	}

	log.Debugf("expandClusterResourceByName returns %v", rs)
	return rs
}

// canGetAllNamespaces determines whether the user is able to get all Namespaces.
func (u *userCalculator) canGetAllNamespaces() bool {
	if u.canGetAllNamespacesVal == nil {
		allNamespaces := rbac_auth.RulesAllow(authorizer.AttributesRecord{
			Verb:            string(VerbGet),
			APIGroup:        "",
			Resource:        resourceNamespaces,
			Name:            "",
			ResourceRequest: true,
		}, u.getClusterRules()...)
		u.canGetAllNamespacesVal = &allNamespaces
		log.Debugf("canGetAllNamespaces returns %v", u.canGetAllNamespacesVal)
	}

	return *u.canGetAllNamespacesVal
}

// getAllNamespaces returns the current set of configured Namespaces.
func (u *userCalculator) getAllNamespaces() []types.NamespacedName {
	if u.allNamespaces == nil {
		if namespaces, err := u.calculator.namespaceLister.ListNamespaces(); err != nil {
			log.WithError(err).Debug("Failed to list Namespaces")
			u.errors = append(u.errors, err)
			u.allNamespaces = make([]types.NamespacedName, 0)
		} else {
			for _, namespace := range namespaces {
				u.allNamespaces = append(u.allNamespaces, types.NamespacedName{Name: namespace.Name})
			}
		}
		log.Debugf("getAllNamespaces returns %v", u.allNamespaces)
	}

	return u.allNamespaces
}

// getGettableNamespaces determines which Namespaces the user is able to get.
func (u *userCalculator) getGettableNamespaces() []types.NamespacedName {
	if u.gettableNamespaces == nil {
		for _, namespace := range u.getAllNamespaces() {
			if u.canGetAllNamespaces() || rbac_auth.RulesAllow(authorizer.AttributesRecord{
				Verb:            string(VerbGet),
				APIGroup:        v3.Group,
				Resource:        resourceNamespaces,
				Name:            namespace.Name,
				ResourceRequest: true,
			}, u.getClusterRules()...) {
				u.gettableNamespaces = append(u.gettableNamespaces, namespace)
			}
		}
		log.Debugf("getGettableNamespaces returns %v", u.gettableNamespaces)
	}

	return u.gettableNamespaces
}

// getClusterRules returns the cluster rules that apply to the user.
func (u *userCalculator) getClusterRules() []rbacv1.PolicyRule {
	if u.clusterRules == nil {
		// ClusterRuleResolver returns aggregated errors when matching rules
		rules, errors := u.calculator.clusterRuleResolver.RulesFor(u.user, "")
		if errors != nil {
			log.WithError(errors).Debug("Failed to list cluster-wide rules for user")
			// Filter out NotFound error for any missing cluster role to match the k8s API
			curatedError := utilerrors.FilterOut(errors, func(err error) bool {
				return k8serrors.IsNotFound(err)
			})
			if curatedError != nil {
				u.errors = append(u.errors, curatedError)
			}
		}

		// Set matched rules
		if rules != nil {
			u.clusterRules = rules
		} else {
			u.clusterRules = make([]rbacv1.PolicyRule, 0)
		}

		log.Debugf("getClusterRules returns %v", u.clusterRules)
	}

	return u.clusterRules
}

// getNamespacedRules returns the namespaced rules that apply to the user.
func (u *userCalculator) getNamespacedRules() map[string][]rbacv1.PolicyRule {
	if u.namespacedRules == nil {
		u.namespacedRules = make(map[string][]rbacv1.PolicyRule)
		if namespaces, err := u.calculator.namespaceLister.ListNamespaces(); err != nil {
			log.WithError(err).Debug("Failed to list namespaced rules for user")
			u.errors = append(u.errors, err)
		} else {
			for _, n := range namespaces {
				rules, errors := u.calculator.namespacedRuleResolver.RulesFor(u.user, n.Name)

				// Filter out NotFound error for any missing cluster role to match the k8s API
				curatedError := utilerrors.FilterOut(errors, func(err error) bool {
					return k8serrors.IsNotFound(err)
				})
				if curatedError != nil {
					u.errors = append(u.errors, curatedError)
				} else if len(rules) > 0 {
					u.namespacedRules[n.Name] = rules
				}
			}
		}
		log.Debugf("getNamespacedRules returns %v", u.namespacedRules)
	}
	return u.namespacedRules
}

func (u *userCalculator) Calculate(rvs []ResourceVerbs) (Permissions, error) {
	for _, rv := range rvs {
		u.updatePermissions(rv.ResourceType, rv.Verbs)
	}
	return u.permissions, utilerrors.Flatten(utilerrors.NewAggregate(u.errors))
}

// updatePermissions calculates the RBAC permissions for a specific resource type and set of verbs, and updates the
// Permissions response struct.
func (u *userCalculator) updatePermissions(rt ResourceType, verbs []Verb) {
	// Remove the sub-resource if present.
	parts := strings.SplitN(rt.Resource, "/", 2)
	mainresource := ResourceType{
		APIGroup: rt.APIGroup,
		Resource: parts[0],
	}
	var subresource string
	if len(parts) == 2 {
		subresource = parts[1]
	}

	// Look up the APIResource info for the primary resource (i.e. not the subresource).
	ar, ok := u.resources[mainresource]
	if !ok && !u.resourcesUpdated {
		// This is an unknown resource type, we permit an update of the resources at most once per request.
		log.Debugf("Resource type %s not found, update cached resource types", rt)
		u.resourcesUpdated = true
		u.updateResources()
		ar, ok = u.resources[rt]
	}

	u.permissions[rt] = make(map[Verb][]Match)
	for _, verb := range verbs {
		log.Debugf("Accumulating results for: %s %s", verb, rt)
		if ok {
			// The resource is registered so determine the matches from the RBAC config.
			u.permissions[rt][verb] = u.getMatches(verb, ar, subresource)
		} else {
			// The resource is not registered so do not add any matches for this resource/verb combination.
			u.permissions[rt][verb] = nil
		}
	}
}

func (u *userCalculator) updateResources() {
	// Grab the resource lock
	u.calculator.resourceLock.Lock()
	defer u.calculator.resourceLock.Unlock()

	if u.calculator.resourceUpdateTime == u.resourcesUpdateTime {
		// The cache has not been updated since the query began, so update it now.  If any errors occur the cache will
		// not be updated and the data will remain out-of-date - this is fine, we'll simply not include the results.
		err := u.calculator.loadResources()
		if err != nil {
			log.WithError(err).Warnf("Unable to update registered resource list - calculated RBAC may be incomplete")
			return
		}
	}

	// Update the user-specific cache to point to the current cache.
	log.Debug("Update user calculator to use updated cache of known resource types")
	u.resources = u.calculator.resources
	u.resourcesUpdateTime = u.calculator.resourceUpdateTime
}
