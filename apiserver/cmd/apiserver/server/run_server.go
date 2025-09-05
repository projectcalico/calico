// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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

	klog.Infof("Enabling ValidatingAdmissionPolicy: %v", opts.EnableValidatingAdmissionPolicy)
	if !opts.EnableValidatingAdmissionPolicy {
		opts.RecommendedOptions.Admission = options.NewAdmissionOptions()
		opts.RecommendedOptions.Admission.DisablePlugins = []string{validating.PluginName}
	}
	config, err := opts.Config()
	if err != nil {
		return nil, err
	}

	logrus.Debug("Completing API server configuration")
	return config.Complete().New()
}

// RunServer runs the Calico API server.  This blocks until stopped channel (passed in through options) is closed.
func RunServer(opts *CalicoServerOptions, server *apiserver.ProjectCalicoServer) error {
	// Create a context rather than using the stop channel - it's a little more versatile.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Wait for the stop channel and cancel.
		select {
		case <-opts.StopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	go func() {
		logrus.Info("Starting watch extension")
		changed, err := WatchExtensionAuth(ctx)
		if err != nil {
			logrus.Error("Unable to watch the extension auth ConfigMap: ", err)
		}
		if changed {
			logrus.Info("Detected change in extension-apiserver-authentication ConfigMap, exiting so apiserver can be restarted")
			cancel()
		}
	}()

	go func() {
		logrus.Info("Running the API server")

		// Start the Calico resource handler and shared informers and wait for sync before starting other components.
		server.CalicoResourceLister.Start()
		server.WatchManager.Start()
		server.SharedInformerFactory.Start(ctx.Done())
		server.CalicoResourceLister.WaitForCacheSync(ctx.Done())
		server.WatchManager.WaitForCacheSync(ctx.Done())
		server.SharedInformerFactory.WaitForCacheSync(ctx.Done())

		if opts.PrintSwagger {
			if err := server.GenericAPIServer.AddPostStartHook("swagger-printer",
				func(context genericapiserver.PostStartHookContext) error {
					WriteSwaggerJSON(server.GenericAPIServer.Handler, opts.SwaggerFilePath)
					// PrintSwagger option prints and exit.
					os.Exit(0)
					return nil
				}); err != nil {
				logrus.Error("failed to add post start hook swagger-printer:", err)
			}
		}
		if err := server.GenericAPIServer.PrepareRun().RunWithContext(ctx); err != nil {
			logrus.Error("Error running API server: ", err)
		}
	}()

	// Wait until the context is done.
	<-ctx.Done()

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
