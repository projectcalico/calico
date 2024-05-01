// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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
	"os"

	genericoptions "k8s.io/apiserver/pkg/server/options"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/apiserver/pkg/apiserver"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"

	"k8s.io/kubernetes/pkg/util/interrupt"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

const defaultEtcdPathPrefix = ""

func logrusLevel() logrus.Level {
	if env := os.Getenv("LOG_LEVEL"); env != "" {
		return logutils.SafeParseLogLevel(env)
	}

	if klog.V(2).Enabled() {
		return logrus.DebugLevel
	}
	if klog.V(1).Enabled() {
		return logrus.InfoLevel
	}
	return logrus.ErrorLevel
}

// NewCommandStartMaster provides a CLI handler for 'start master' command
func NewCommandStartCalicoServer(out io.Writer) (*cobra.Command, error) {
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

	stopCh := make(chan struct{})

	ro := genericoptions.NewRecommendedOptions(defaultEtcdPathPrefix, apiserver.Codecs.LegacyCodec(v3.SchemeGroupVersion))
	opts := &CalicoServerOptions{
		RecommendedOptions: ro,
		StopCh:             stopCh,
	}
	opts.addFlags(flags)

	cmd.Run = func(c *cobra.Command, args []string) {
		logrus.SetLevel(logrusLevel())

		h := interrupt.New(nil, func() {
			close(stopCh)
		})
		if err := h.Run(func() error {
			server, err := PrepareServer(opts)
			if err != nil {
				return err
			}
			return RunServer(opts, server)
		}); err != nil {
			klog.Fatalf("error running server (%s)", err)
			return
		}
	}

	return cmd, nil
}
