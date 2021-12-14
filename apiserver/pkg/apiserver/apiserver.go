// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

package apiserver

import (
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/version"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	calicorest "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/rest"
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
	GenericAPIServer *genericapiserver.GenericAPIServer
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
	c := completedConfig{
		cfg.GenericConfig.Complete(),
		&cfg.ExtraConfig,
	}

	c.GenericConfig.Version = &version.Info{
		Major: "1",
		Minor: "0",
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

	s := &ProjectCalicoServer{GenericAPIServer: genericServer}

	apiGroupInfo.VersionedResourcesStorageMap["v3"], err = calicostore.NewV3Storage(
		Scheme, c.GenericConfig.RESTOptionsGetter, c.GenericConfig.Authorization.Authorizer,
	)
	if err != nil {
		return nil, err
	}

	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	return s, nil
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
