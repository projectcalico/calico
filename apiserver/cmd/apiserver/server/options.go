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

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	k8sopenapi "k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/features"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/klog/v2"
	"k8s.io/kube-openapi/pkg/validation/spec"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"

	"github.com/projectcalico/api/pkg/openapi"

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
	serverConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(openapi.GetOpenAPIDefinitions, k8sopenapi.NewDefinitionNamer(apiserver.Scheme))
	if serverConfig.OpenAPIConfig.Info == nil {
		serverConfig.OpenAPIConfig.Info = &spec.Info{}
	}
	if serverConfig.OpenAPIConfig.Info.Version == "" {
		if serverConfig.Version != nil {
			serverConfig.OpenAPIConfig.Info.Version = strings.Split(serverConfig.Version.String(), "-")[0]
		} else {
			serverConfig.OpenAPIConfig.Info.Version = "unversioned"
		}
	}

	if err := o.RecommendedOptions.Etcd.Complete(serverConfig.StorageObjectCountTracker, serverConfig.DrainedNotify(), serverConfig.AddPostStartHook); err != nil {
		return nil, err
	}
	if err := o.RecommendedOptions.Etcd.ApplyTo(&serverConfig.Config); err != nil {
		return nil, err
	}
	o.RecommendedOptions.Etcd.StorageConfig.Paging = utilfeature.DefaultFeatureGate.Enabled(features.APIListChunking)
	if err := o.RecommendedOptions.SecureServing.ApplyTo(&serverConfig.SecureServing, &serverConfig.LoopbackClientConfig); err != nil {
		return nil, err
	}

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
		if err := o.RecommendedOptions.Authorization.ApplyTo(&serverConfig.Authorization); err != nil {
			return nil, err
		}
	} else {
		// always warn when auth is disabled, since this should only be used for testing
		klog.Infof("Authentication and authorization disabled for testing purposes")
	}

	if err := o.RecommendedOptions.Audit.ApplyTo(&serverConfig.Config); err != nil {
		return nil, err
	}
	if err := o.RecommendedOptions.Features.ApplyTo(&serverConfig.Config); err != nil {
		return nil, err
	}

	if err := o.RecommendedOptions.CoreAPI.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	if initializers, err := o.RecommendedOptions.ExtraAdmissionInitializers(serverConfig); err != nil {
		return nil, err
	} else if err := o.RecommendedOptions.Admission.ApplyTo(&serverConfig.Config, serverConfig.SharedInformerFactory, serverConfig.ClientConfig, o.RecommendedOptions.FeatureGate, initializers...); err != nil {
		return nil, err
	}

	// Extra extra config from environments.
	//TODO(rlb): Need to unify our logging libraries
	logrusLevel := logrus.InfoLevel
	if env := os.Getenv("LOG_LEVEL"); env != "" {
		logrusLevel = logutils.SafeParseLogLevel(env)
	}
	logrus.SetLevel(logrusLevel)

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
