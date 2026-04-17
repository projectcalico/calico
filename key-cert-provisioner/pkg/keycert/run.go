// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package keycert

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/key-cert-provisioner/pkg/cfg"
	"github.com/projectcalico/calico/key-cert-provisioner/pkg/k8s"
	"github.com/projectcalico/calico/key-cert-provisioner/pkg/tls"
)

// Run performs the certificate provisioning workflow. It creates a CSR, submits it to the
// Kubernetes API, and waits for it to be signed. It blocks until the certificate is obtained
// or the context is cancelled.
func Run(ctx context.Context) {
	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetReportCaller(true)

	config := cfg.GetConfigOrDie()
	ctx, cancel := context.WithTimeout(ctx, config.TimeoutDuration)
	defer cancel()

	done := make(chan bool, 1)
	go func() {
		restClient, err := k8s.NewRestClient()
		if err != nil {
			logrus.WithError(err).Fatal("Unable to create a kubernetes rest client")
		}

		csr, err := tls.CreateX509CSR(config)
		if err != nil {
			logrus.WithError(err).Fatal("Unable to create x509 certificate request")
		}

		if err := k8s.SubmitCSR(ctx, config, restClient.Clientset, csr); err != nil {
			logrus.WithError(err).Fatal("Unable to submit a CSR")
		}

		if err := k8s.WatchAndWriteCSR(ctx, restClient.Clientset, config, csr); err != nil {
			logrus.WithError(err).Fatal("Unable to watch or write a CSR")
		}
		done <- true
	}()

	select {
	case <-done:
		logrus.Info("successfully obtained a certificate")
	case <-ctx.Done():
		logrus.Fatal("timeout expired, exiting program with exit code 1")
	}
}
