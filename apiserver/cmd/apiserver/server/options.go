// Copyright (c) 2021 Tigera, Inc. All rights reserved.

/*
Copyright 2017 The Kubernetes Authors.

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

package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/projectcalico/api/pkg/openapi"
	"github.com/spf13/pflag"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	k8sopenapi "k8s.io/apiserver/pkg/endpoints/openapi"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"github.com/projectcalico/calico/apiserver/pkg/apiserver"
)

// CalicoServerOptions contains the aggregation of configuration structs for
// the calico server. It contains everything needed to configure a basic API server.
// It is public so that integration tests can access it.
type CalicoServerOptions struct {
	RecommendedOptions *genericoptions.RecommendedOptions

	// DisableAuth disables delegating authentication and authorization for testing scenarios
	DisableAuth bool

	// Print a swagger file at desired path and exit.
	PrintSwagger    bool
	SwaggerFilePath string

	// Enable Admission Controller support.
	EnableAdmissionController bool

	StopCh <-chan struct{}
}

func (s *CalicoServerOptions) addFlags(flags *pflag.FlagSet) {
	s.RecommendedOptions.AddFlags(flags)

	flags.BoolVar(&s.EnableAdmissionController, "enable-admission-controller-support", s.EnableAdmissionController,
		"If true, admission controller hooks will be enabled.")
	flags.BoolVar(&s.PrintSwagger, "print-swagger", false,
		"If true, prints swagger to stdout and exits.")
	flags.StringVar(&s.SwaggerFilePath, "swagger-file-path", "./",
		"If print-swagger is set true, then write swagger.json to location specified. Default is current directory.")
}

func (o CalicoServerOptions) Validate(args []string) error {
	errors := []error{}
	errors = append(errors, o.RecommendedOptions.Validate()...)
	return utilerrors.NewAggregate(errors)
}

func (o *CalicoServerOptions) Complete() error {
	return nil
}

func (o *CalicoServerOptions) Config() (*apiserver.Config, error) {
	// TODO have a "real" external address
	if err := o.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	serverConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)
	namer := k8sopenapi.NewDefinitionNamer(apiserver.Scheme)
	version := "unversioned"
	if serverConfig.Version != nil {
		version = strings.Split(serverConfig.Version.String(), "-")[0]
	}
	serverConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(openapi.GetOpenAPIDefinitions, namer)
	if serverConfig.OpenAPIConfig.Info.Version == "" {
		serverConfig.OpenAPIConfig.Info.Version = version
	}
	serverConfig.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(openapi.GetOpenAPIDefinitions, namer)
	if serverConfig.OpenAPIV3Config.Info.Version == "" {
		serverConfig.OpenAPIV3Config.Info.Version = version
	}

	// k8s v1.27 enables APIServerTracing feature gate by default [1].
	// When newETCD3Client is constructed within newETCD3Prober,
	// otelgrpc is added as part of the tracingOpts [2]. Even with the Noop
	// TracerProvider, we notice growing memory usage by the opentelemetry
	// internal int64/float64 histograms. As an extension apiserver,
	// we don't config etcd ServerList so skip the health check.
	// [1] https://kubernetes.io/docs/concepts/cluster-administration/system-traces/#kube-apiserver-traces
	// [2] https://github.com/kubernetes/kubernetes/blob/bee599726d8f593a23b0e22fcc01e963732ea40b/staging/src/k8s.io/apiserver/pkg/storage/storagebackend/factory/etcd3.go#L300
	o.RecommendedOptions.Etcd.SkipHealthEndpoints = true
	if err := o.RecommendedOptions.Etcd.ApplyTo(&serverConfig.Config); err != nil {
		return nil, err
	}
	if err := o.RecommendedOptions.SecureServing.ApplyTo(&serverConfig.SecureServing, &serverConfig.LoopbackClientConfig); err != nil {
		return nil, err
	}

	// We now build the APIServer against >= k8s v1.29.
	// FlowControl API resources graduated to v1 in this version,
	// so if we run this APIServer on a backlevel (<v1.29) cluster,
	// it will never go ready, due to a failed fetch of the v1 resources.
	o.RecommendedOptions.Features.EnablePriorityAndFairness = false

	// Explicitly setting cipher suites in order to remove deprecated ones
	// The list is taken from https://github.com/golang/go/blob/dev.boringcrypto.go1.13/src/crypto/tls/boring.go#L54
	cipherSuites := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
	serverConfig.SecureServing.CipherSuites = cipherSuites
	serverConfig.SecureServing.MinTLSVersion = tls.VersionTLS12

	if o.PrintSwagger {
		o.DisableAuth = true
	}
	if !o.DisableAuth {
		if err := o.RecommendedOptions.Authentication.ApplyTo(&serverConfig.Authentication, serverConfig.SecureServing, serverConfig.OpenAPIConfig); err != nil {
			return nil, err
		}

		// Prevent /readyz from bypassing authorization. This makes /readyz perform authorization against kube-apiserver,
		// and therefore makes /readyz a better indication of whether the container is capable of handling requests.
		var filteredAlwaysAllowPaths []string
		for _, path := range o.RecommendedOptions.Authorization.AlwaysAllowPaths {
			if path != "/readyz" {
				filteredAlwaysAllowPaths = append(filteredAlwaysAllowPaths, path)
			}
		}
		o.RecommendedOptions.Authorization.AlwaysAllowPaths = filteredAlwaysAllowPaths
		if err := o.RecommendedOptions.Authorization.ApplyTo(&serverConfig.Authorization); err != nil {
			return nil, err
		}
	} else {
		// Validating Admission Policy is generally available in k8s 1.30 [1].
		// The admission plugin "ValidatingAdmissionPolicy" fails to initialize due to
		// a missing authorizer. When DisableAuth=true, we need a always allow authorizer
		// to pass ValidateInitialization checks.
		// [1] https://kubernetes.io/blog/2024/04/24/validating-admission-policy-ga/
		serverConfig.Authorization.Authorizer = authorizerfactory.NewAlwaysAllowAuthorizer()
		// always warn when auth is disabled, since this should only be used for testing
		klog.Infof("Authentication and authorization disabled for testing purposes")
	}

	if err := o.RecommendedOptions.Audit.ApplyTo(&serverConfig.Config); err != nil {
		return nil, err
	}

	if err := o.RecommendedOptions.CoreAPI.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	kubeClient, err := kubernetes.NewForConfig(serverConfig.ClientConfig)
	if err != nil {
		return nil, err
	}

	dynamicClient, err := dynamic.NewForConfig(serverConfig.ClientConfig)
	if err != nil {
		return nil, err
	}

	if err := o.RecommendedOptions.Features.ApplyTo(&serverConfig.Config, kubeClient, serverConfig.SharedInformerFactory); err != nil {
		return nil, err
	}

	if initializers, err := o.RecommendedOptions.ExtraAdmissionInitializers(serverConfig); err != nil {
		return nil, err
	} else if err := o.RecommendedOptions.Admission.ApplyTo(
		&serverConfig.Config,
		serverConfig.SharedInformerFactory,
		kubeClient,
		dynamicClient,
		o.RecommendedOptions.FeatureGate,
		initializers...); err != nil {
		return nil, err
	}

	// disable unused apiserver profiling and metrics
	serverConfig.EnableContentionProfiling = false
	serverConfig.EnableMetrics = false
	serverConfig.EnableProfiling = false

	minResourceRefreshInterval := 5 * time.Second
	if env := os.Getenv("MIN_RESOURCE_REFRESH_INTERVAL"); env != "" {
		if dur, err := time.ParseDuration(env); err != nil {
			return nil, err
		} else {
			minResourceRefreshInterval = dur
		}
	}

	config := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig: apiserver.ExtraConfig{
			KubernetesAPIServerConfig:  serverConfig.ClientConfig,
			MinResourceRefreshInterval: minResourceRefreshInterval,
		},
	}

	return config, nil
}
