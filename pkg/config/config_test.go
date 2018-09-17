// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package config_test

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/kube-controllers/pkg/config"
)

var _ = Describe("Config", func() {

	// unsetEnv() function that unsets environment variables
	// required by kube-controllers controller
	unsetEnv := func() {
		os.Unsetenv("LOG_LEVEL")
		os.Unsetenv("RECONCILER_PERIOD")
		os.Unsetenv("ENABLED_CONTROLLERS")
		os.Unsetenv("WORKLOAD_ENDPOINT_WORKERS")
		os.Unsetenv("PROFILE_WORKERS")
		os.Unsetenv("POLICY_WORKERS")
		os.Unsetenv("KUBECONFIG")
	}

	// setEnv() function that sets environment variables
	// to some sensbile values
	setEnv := func() {
		os.Setenv("LOG_LEVEL", "debug")
		os.Setenv("RECONCILER_PERIOD", "2m5s")
		os.Setenv("ENABLED_CONTROLLERS", "policy")
		os.Setenv("WORKLOAD_ENDPOINT_WORKERS", "3")
		os.Setenv("PROFILE_WORKERS", "3")
		os.Setenv("POLICY_WORKERS", "3")
		os.Setenv("KUBECONFIG", "/home/user/.kube/config")
	}

	// setWrongEnv() function sets environment variables
	// with values of wrong data type
	setWrongEnv := func() {
		os.Setenv("WORKLOAD_ENDPOINT_WORKERS", "somestring")
		os.Setenv("PROFILE_WORKERS", "somestring")
		os.Setenv("POLICY_WORKERS", "somestring")
	}

	Context("with default values", func() {

		// Unset environment variables
		unsetEnv()

		// Parse config
		config := new(config.Config)
		err := config.Parse()

		// Assert no error generated
		It("shoud not generate error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert default values
		It("shoud return default values", func() {
			Expect(config.LogLevel).To(Equal("info"))
			Expect(config.ReconcilerPeriod).To(Equal("5m"))
			Expect(config.EnabledControllers).To(Equal("node,policy,namespace,workloadendpoint,serviceaccount"))
			Expect(config.WorkloadEndpointWorkers).To(Equal(1))
			Expect(config.ProfileWorkers).To(Equal(1))
			Expect(config.PolicyWorkers).To(Equal(1))
			Expect(config.Kubeconfig).To(Equal(""))
		})
	})

	Context("with valid user defined values", func() {

		// Set environment variables
		setEnv()

		// Reset environment variables
		defer unsetEnv()

		// Parse config
		config := new(config.Config)
		err := config.Parse()

		// Assert no error generated
		It("shoud not generate error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert values
		It("shoud return user defined values", func() {
			Expect(config.LogLevel).To(Equal("debug"))
			Expect(config.ReconcilerPeriod).To(Equal("2m5s"))
			Expect(config.EnabledControllers).To(Equal("policy"))
			Expect(config.WorkloadEndpointWorkers).To(Equal(3))
			Expect(config.ProfileWorkers).To(Equal(3))
			Expect(config.PolicyWorkers).To(Equal(3))
			Expect(config.Kubeconfig).To(Equal("/home/user/.kube/config"))
		})
	})

	Context("with invalid user defined values", func() {

		// Set wrong environment variables
		setWrongEnv()

		// Reset environment variables
		defer unsetEnv()

		// Parse config
		config := new(config.Config)
		err := config.Parse()

		// Assert error is generated
		It("shoud generate error", func() {
			Expect(err).To(HaveOccurred())
		})
	})
})
