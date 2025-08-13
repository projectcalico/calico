// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.

package apiserver

import (
	"context"
	"sync"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/informers"
	corev1listers "k8s.io/client-go/listers/core/v1"
	rbacv1listers "k8s.io/client-go/listers/rbac/v1"
	"k8s.io/client-go/rest"
	utilversion "k8s.io/component-base/version"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	calicorest "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/rest"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/util"
	"github.com/projectcalico/calico/apiserver/pkg/storage/calico"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
)

var (
	Scheme        = runtime.NewScheme()
	Codecs        = serializer.NewCodecFactory(Scheme)
	GroupName     = v3.GroupName
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func init() {
	install(Scheme)

	// we need to add the options to empty v1
	// TODO fix the server code to avoid this
	metav1.AddToGroupVersion(Scheme, schema.GroupVersion{Version: "v1"})

	// TODO: keep the generic API server from wanting this
	unversioned := schema.GroupVersion{Group: "", Version: "v1"}
	Scheme.AddUnversionedTypes(unversioned,
		&metav1.Status{},
		&metav1.APIVersions{},
		&metav1.APIGroupList{},
		&metav1.APIGroup{},
		&metav1.APIResourceList{},
	)
}

type ExtraConfig struct {
	// Place you custom config here.
	KubernetesAPIServerConfig  *rest.Config
	MinResourceRefreshInterval time.Duration
}

type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

// ProjectCalicoServer contains state for a Kubernetes cluster master/api server.
type ProjectCalicoServer struct {
	GenericAPIServer      *genericapiserver.GenericAPIServer
	RBACCalculator        rbac.Calculator
	CalicoResourceLister  CalicoResourceLister
	WatchManager          *util.WatchManager
	SharedInformerFactory informers.SharedInformerFactory
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	ExtraConfig   *ExtraConfig
}

type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (cfg *Config) Complete() CompletedConfig {
	cfg.GenericConfig.EffectiveVersion = utilversion.NewEffectiveVersion("1.0")
	c := completedConfig{
		cfg.GenericConfig.Complete(),
		&cfg.ExtraConfig,
	}

	return CompletedConfig{&c}
}

// New returns a new instance of ProjectCalicoServer from the given config.
func (c completedConfig) New() (*ProjectCalicoServer, error) {
	genericServer, err := c.GenericConfig.New("apiserver", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(GroupName, Scheme, metav1.ParameterCodec, Codecs)
	apiGroupInfo.NegotiatedSerializer = newProtocolShieldSerializer(&Codecs)

	// TODO: Make the storage type configurable
	calicostore := calicorest.RESTStorageProvider{StorageType: "calico"}

	// Create a backend Calico v3 clientset.
	cc := calico.CreateClientFromConfig().(backendClient).Backend()

	// Create the various lister and getters required by the RBAC calculator. Note that we use an informer/cache for the
	// k8s resources to minimize the number of queries underpinning a single request. For the Calico resources we
	// implement our own syncer-based cache.
	calicoLister := NewCalicoResourceLister(cc)

	// Create the manager for policy watches. It keeps track of established watches and makes sure they are canceled
	// in case of on update that the watch necessitates recreation of the watch.
	watchManager := util.NewWatchManager(cc)

	// Create the RBAC calculator,
	calculator, err := c.NewRBACCalculator(calicoLister)
	if err != nil {
		return nil, err
	}

	s := &ProjectCalicoServer{
		GenericAPIServer:      genericServer,
		RBACCalculator:        calculator,
		CalicoResourceLister:  calicoLister,
		WatchManager:          watchManager,
		SharedInformerFactory: c.GenericConfig.SharedInformerFactory,
	}

	apiGroupInfo.VersionedResourcesStorageMap["v3"], err = calicostore.NewV3Storage(
		Scheme, c.GenericConfig.RESTOptionsGetter, c.GenericConfig.Authorization.Authorizer, calicoLister, watchManager)
	if err != nil {
		return nil, err
	}

	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	return s, nil
}

func (c completedConfig) NewRBACCalculator(calicoLister CalicoResourceLister) (rbac.Calculator, error) {
	resourceLister := discovery.NewDiscoveryClientForConfigOrDie(c.ExtraConfig.KubernetesAPIServerConfig)
	namespaceLister := &k8sNamespaceLister{c.GenericConfig.SharedInformerFactory.Core().V1().Namespaces().Lister()}
	roleGetter := &K8sRoleGetter{c.GenericConfig.SharedInformerFactory.Rbac().V1().Roles().Lister()}
	roleBindingLister := &K8sRoleBindingLister{c.GenericConfig.SharedInformerFactory.Rbac().V1().RoleBindings().Lister()}
	clusterRoleGetter := &K8sClusterRoleGetter{c.GenericConfig.SharedInformerFactory.Rbac().V1().ClusterRoles().Lister()}
	clusterRoleBindingLister := &K8sClusterRoleBindingLister{c.GenericConfig.SharedInformerFactory.Rbac().V1().ClusterRoleBindings().Lister()}

	// Create the rbac calculator
	return rbac.NewCalculator(
		resourceLister, clusterRoleGetter, clusterRoleBindingLister, roleGetter, roleBindingLister,
		namespaceLister, calicoLister, c.ExtraConfig.MinResourceRefreshInterval,
	), nil
}

// K8sRoleGetter implements the RoleGetter interface returning matching Role.
type K8sRoleGetter struct {
	Lister rbacv1listers.RoleLister
}

func (r *K8sRoleGetter) GetRole(ctx context.Context, namespace, name string) (*rbacv1.Role, error) {
	return r.Lister.Roles(namespace).Get(name)
}

// K8sRoleBindingLister implements the RoleBindingLister interface returning RoleBindings.
type K8sRoleBindingLister struct {
	Lister rbacv1listers.RoleBindingLister
}

func (r *K8sRoleBindingLister) ListRoleBindings(ctx context.Context, namespace string) ([]*rbacv1.RoleBinding, error) {
	return r.Lister.RoleBindings(namespace).List(labels.Everything())
}

// K8sClusterRoleGetter implements the ClusterRoleGetter interface returning matching ClusterRole.
type K8sClusterRoleGetter struct {
	Lister rbacv1listers.ClusterRoleLister
}

func (r *K8sClusterRoleGetter) GetClusterRole(ctx context.Context, name string) (*rbacv1.ClusterRole, error) {
	return r.Lister.Get(name)
}

// K8sClusterRoleBindingLister implements the ClusterRoleBindingLister interface.
type K8sClusterRoleBindingLister struct {
	Lister rbacv1listers.ClusterRoleBindingLister
}

func (r *K8sClusterRoleBindingLister) ListClusterRoleBindings(ctx context.Context) ([]*rbacv1.ClusterRoleBinding, error) {
	return r.Lister.List(labels.Everything())
}

func NewNamepaceLister(sharedInformerFactory informers.SharedInformerFactory) rbac.NamespaceLister {
	return &k8sNamespaceLister{
		namespaceLister: sharedInformerFactory.Core().V1().Namespaces().Lister(),
	}
}

// k8sNamespaceLister implements the NamespaceLister interface returning Namespaces.
type k8sNamespaceLister struct {
	namespaceLister corev1listers.NamespaceLister
}

func (n *k8sNamespaceLister) ListNamespaces() ([]*corev1.Namespace, error) {
	return n.namespaceLister.List(labels.Everything())
}

func NewCalicoResourceLister(cc api.Client) CalicoResourceLister {
	return &calicoResourceLister{
		client: cc,
		tiers:  make(map[string]*v3.Tier),
	}
}

type CalicoResourceLister interface {
	Start()
	WaitForCacheSync(stopCh <-chan struct{})
	ListTiers() ([]*v3.Tier, error)
}

// calicoResourceLister implements the CalicoResourceLister interface returning Tiers.
type calicoResourceLister struct {
	client api.Client
	syncer api.Syncer
	lock   sync.Mutex
	sync   chan struct{}
	tiers  map[string]*v3.Tier
}

func (t *calicoResourceLister) ListTiers() ([]*v3.Tier, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	tiers := make([]*v3.Tier, 0, len(t.tiers))
	for _, tier := range t.tiers {
		tiers = append(tiers, tier)
	}
	return tiers, nil
}

func (t *calicoResourceLister) Start() {
	t.sync = make(chan struct{})
	t.syncer = watchersyncer.New(
		t.client,
		[]watchersyncer.ResourceType{
			{ListInterface: model.ResourceListOptions{Kind: v3.KindTier}},
		},
		t,
	)
	t.syncer.Start()
}

func (t *calicoResourceLister) WaitForCacheSync(stopCh <-chan struct{}) {
	select {
	case <-t.sync:
	case <-stopCh:
	}
}

func (t *calicoResourceLister) OnStatusUpdated(status api.SyncStatus) {
	if status == api.InSync {
		close(t.sync)
	}
}

func (t *calicoResourceLister) OnUpdates(updates []api.Update) {
	t.lock.Lock()
	defer t.lock.Unlock()
	for _, u := range updates {
		// The syncer API is sort of broken in that there are scenarios in which you can receive a KVUpdate that is actually a delete.
		// The correct way to tell if an update on the syncer API is a delete operation or not is to check if u.KVPair.Value == nil.
		// If it's nil, it should be treated as a delete regardless of the update type, and if it's non-nil it should be treated as an add / update.
		isDelete := func(u api.Update) bool {
			return u.KVPair.Value == nil
		}

		switch u.Key.(model.ResourceKey).Kind {
		case v3.KindTier:
			if isDelete(u) {
				delete(t.tiers, u.Key.(model.ResourceKey).Name)
			} else {
				t.tiers[u.Key.(model.ResourceKey).Name] = u.Value.(*v3.Tier)
			}
		}
	}
}

type backendClient interface {
	Backend() api.Client
}

// install registers the API group and adds types to a scheme
func install(scheme *runtime.Scheme) {
	utilruntime.Must(v3.AddToScheme(scheme))
	utilruntime.Must(AddToScheme(scheme))
	utilruntime.Must(scheme.SetVersionPriority(v3.SchemeGroupVersion))
}

// Adds the list of known types to Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	// At the moment the v3 API is identical to the internal API. Register the same set of definitions as the
	// internal set, no conversions are required since they are identical.
	scheme.AddKnownTypes(v3.SchemeGroupVersionInternal, v3.AllKnownTypes...)
	return nil
}
