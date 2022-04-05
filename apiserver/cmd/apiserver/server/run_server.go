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
	"fmt"
	"io"
	"net/http"
	"os"
	gpath "path"

	genericapiserver "k8s.io/apiserver/pkg/server"
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

	config, err := opts.Config()
	if err != nil {
		return nil, err
	}

	klog.V(4).Infoln("Completing API server configuration")
	return config.Complete().New()
}

// RunServer runs the Calico API server.  This blocks until stopped channel (passed in through options) is closed.
func RunServer(opts *CalicoServerOptions, server *apiserver.ProjectCalicoServer) error {
	readinessPath := "/tmp/ready"
	_ = os.Remove(readinessPath)

	allStop := make(chan struct{})
	go func() {
		klog.Infoln("Starting watch extension")
		changed, err := WatchExtensionAuth(allStop)
		if err != nil {
			klog.Errorln("Unable to watch the extension auth ConfigMap: ", err)
		}
		if changed {
			klog.Infoln("Detected change in extension-apiserver-authentication ConfigMap, exiting so apiserver can be restarted")
		}
	}()

	go func() {
		klog.Infoln("Running the API server")

		// Add a post-start hook to write the readiness file, which is used for
		// readiness probes.
		server.GenericAPIServer.AddPostStartHook("apiserver-autoregistration",
			func(context genericapiserver.PostStartHookContext) error {
				f, err := os.Create(readinessPath)
				if err != nil {
					klog.Errorln(err)
					return err
				}
				klog.Info("apiserver is ready.")
				f.Close()
				return nil
			})

		if opts.PrintSwagger {
			server.GenericAPIServer.AddPostStartHook("swagger-printer",
				func(context genericapiserver.PostStartHookContext) error {
					WriteSwaggerJSON(server.GenericAPIServer.Handler, opts.SwaggerFilePath)
					// PrintSwagger option prints and exit.
					os.Exit(0)
					return nil
				})
		}
		if err := server.GenericAPIServer.PrepareRun().Run(allStop); err != nil {
			klog.Errorln("Error running API server: ", err)
		}
	}()

	select {
	case <-allStop:
	case <-opts.StopCh:
		close(allStop)
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
	defer f.Close()
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
