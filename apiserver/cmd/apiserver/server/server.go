// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

/*
Copyright 2016 The Kubernetes Authors.

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
	"flag"
	"io"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"

	"github.com/projectcalico/calico/apiserver/pkg/apiserver"
)

const defaultEtcdPathPrefix = ""

// NewCommandStartMaster provides a CLI handler for 'start master' command
func NewCommandStartCalicoServer(out io.Writer) (*cobra.Command, *CalicoServerOptions, error) {
	//	o := NewCalicoServerOptions(out, errOut)

	// Create the command that runs the API server
	cmd := &cobra.Command{
		Short: "run a calico api server",
	}
	// We pass flags object to sub option structs to have them configure
	// themselves. Each options adds its own command line flags
	// in addition to the flags that are defined above.
	flags := cmd.Flags()
	flags.AddGoFlagSet(flag.CommandLine)

	ro := genericoptions.NewRecommendedOptions(defaultEtcdPathPrefix, apiserver.Codecs.LegacyCodec(v3.SchemeGroupVersion))
	opts := &CalicoServerOptions{
		RecommendedOptions: ro,
	}
	opts.addFlags(flags)

	cmd.Run = func(c *cobra.Command, args []string) {
		configureLogging()

		// The first SIGINT or SIGTERM starts graceful shutdown and a second exits immediately. It panics if called
		// twice, so it lives here rather than where the command is built.
		opts.StopCh = genericapiserver.SetupSignalHandler()

		server, err := PrepareServer(opts)
		if err != nil {
			logrus.WithError(err).Fatal("Error preparing the API server")
		}
		if err := RunServer(opts, server); err != nil {
			logrus.WithError(err).Fatal("Error running the API server")
		}
	}

	return cmd, opts, nil
}
