// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	gpath "path"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/admission/plugin/policy/mutating"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/klog/v2"

	"github.com/projectcalico/calico/apiserver/pkg/apiserver"
)

// PrepareServer prepares the server for execution. After invoking the caller should run RunServer.
func PrepareServer(opts *CalicoServerOptions) (*apiserver.ProjectCalicoServer, error) {
	if opts.StopCh == nil {
		/* the caller of RunServer should generate the stop channel
		if there is a need to stop the API server */
		opts.StopCh = make(chan struct{})
	}

	// MAP plugin hard-coded disable — enabling here would break on k8s < 1.36
	// (v1.MutatingAdmissionPolicy doesn't exist on the cluster). As a result,
	// user-defined MAPs against projectcalico.org/v3 won't fire here. To use
	// MAP, Calico should be installed without calico-apiserver, where
	// kube-apiserver serves v3 as CRDs and enforces MAPs directly.
	disabledPlugins := []string{mutating.PluginName}
	klog.Infof("Enabling ValidatingAdmissionPolicy: %v", opts.EnableValidatingAdmissionPolicy)
	if !opts.EnableValidatingAdmissionPolicy {
		disabledPlugins = append(disabledPlugins, validating.PluginName)
	}
	if opts.RecommendedOptions.Admission == nil {
		opts.RecommendedOptions.Admission = options.NewAdmissionOptions()
	}
	opts.RecommendedOptions.Admission.DisablePlugins = append(
		opts.RecommendedOptions.Admission.DisablePlugins, disabledPlugins...,
	)

	config, err := opts.Config()
	if err != nil {
		return nil, err
	}

	logrus.Debug("Completing API server configuration")
	return config.Complete().New()
}

// RunServer runs the Calico API server until the stop channel in opts is closed or the server fails. It returns
// the server's error so a failure exits non-zero. Changes to the client CA and request-header settings in
// kube-system/extension-apiserver-authentication are reloaded by the upstream authenticator, so no restart is needed.
func RunServer(opts *CalicoServerOptions, server *apiserver.ProjectCalicoServer) error {
	// Derive a context from the stop channel so the server also stops when RunServer returns.
	ctx, cancel := context.WithCancel(wait.ContextForChannel(opts.StopCh))
	defer cancel()

	logrus.Info("Running the API server")

	// Start the Calico resource handler and shared informers and wait for sync before starting other components.
	server.CalicoResourceLister.Start()
	server.WatchManager.Start()
	server.SharedInformerFactory.Start(ctx.Done())
	server.CalicoResourceLister.WaitForCacheSync(ctx.Done())
	server.WatchManager.WaitForCacheSync(ctx.Done())
	server.SharedInformerFactory.WaitForCacheSync(ctx.Done())

	if opts.PrintSwagger {
		printSwagger := func(genericapiserver.PostStartHookContext) error {
			WriteSwaggerJSON(server.GenericAPIServer.Handler, opts.SwaggerFilePath)

			// PrintSwagger option prints and exit.
			os.Exit(0)
			return nil
		}
		if err := server.GenericAPIServer.AddPostStartHook("swagger-printer", printSwagger); err != nil {
			logrus.WithError(err).Error("Failed to add post start hook swagger-printer")
		}
	}

	// Block until the context is canceled or the server fails.
	if err := server.GenericAPIServer.PrepareRun().RunWithContext(ctx); err != nil {
		return fmt.Errorf("running API server: %w", err)
	}
	return nil
}

func WriteSwaggerJSON(handler *genericapiserver.APIServerHandler, path string) {
	req, err := http.NewRequest("GET", "/openapi/v2", nil)
	if err != nil {
		panic(fmt.Sprintf("Could not fetch swagger. Reason: %v", err))
	}
	swaggerPath := gpath.Join(path, "swagger.json")
	f, err := os.Create(swaggerPath)
	if err != nil {
		panic(fmt.Sprintf("Could not create file at '%s'. Reason: %v", swaggerPath, err))
	}
	defer func() { _ = f.Close() }()
	resp := &fileResponseWriter{f}
	handler.ServeHTTP(resp, req)
}

// Write response to a file (any io.Writer really).
type fileResponseWriter struct {
	io.Writer
}

func (fileResponseWriter) Header() http.Header {
	return http.Header{}
}

func (fileResponseWriter) WriteHeader(int) {}
