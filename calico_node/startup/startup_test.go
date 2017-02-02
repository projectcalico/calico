// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package main

import (
	"log"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

var exitCode int

func fakeExitFunction(ec int) {
	exitCode = ec
}

var _ = Describe("Non-etcd related tests", func() {

	Describe("Logging tests", func() {
		Context("Test message", func() {
			message("Test message %d, %s", 4, "END")
		})
		Context("Test warning", func() {
			warning("Test message %d, %s", 4, "END")
		})
		Context("Test fatal", func() {
			fatal("Test message %d, %s", 4, "END")
		})
	})

	Describe("Termination tests", func() {
		exitCode = 0
		Context("Test termination", func() {
			oldExit := exitFunction
			exitFunction = fakeExitFunction
			defer func() { exitFunction = oldExit }()
			terminate()
			It("should have terminated", func() {
				Expect(exitCode).To(Equal(1))
			})
		})
	})
})

type EnvItem struct {
	key   string
	value string
}

var _ = Describe("FV tests against a real etcd", func() {
	changedEnvVars := []string{"CALICO_IPV4POOL_CIDR", "CALICO_IPV6POOL_CIDR", "NO_DEFAULT_POOLS"}

	BeforeEach(func() {
		for _, envName := range changedEnvVars {
			os.Unsetenv(envName)
		}
	})
	AfterEach(func() {
		for _, envName := range changedEnvVars {
			os.Unsetenv(envName)
		}
	})

	DescribeTable("Test IP pool env variables",
		func(envList []EnvItem, expectedIPv4 string, expectedIPv6 string, expectIPIP bool) {

			// Erase etcd clean.
			testutils.CleanEtcd()

			// Create a new client.
			c, err := testutils.NewClient("")
			if err != nil {
				log.Println("Error creating client:", err)
			}

			// Set the env variables specified.
			for _, env := range envList {
				os.Setenv(env.key, env.value)
			}
			poolList, err := c.IPPools().List(api.IPPoolMetadata{})
			Expect(poolList.Items).To(BeEmpty())

			// Run the UUT.
			configureIPPools(c)

			// Get the IPPool list.
			poolList, err = c.IPPools().List(api.IPPoolMetadata{})
			Expect(err).NotTo(HaveOccurred())
			log.Println("Get pool list returns: ", poolList.Items)

			// Look through the pool for the expected data.
			foundv4Expected := false
			foundv6Expected := false
			for _, pool := range poolList.Items {
				if pool.Metadata.CIDR.String() == expectedIPv4 {
					foundv4Expected = true
				}
				if pool.Metadata.CIDR.String() == expectedIPv6 {
					foundv6Expected = true
				}
				if expectIPIP {
					Expect(pool.Spec.IPIP.Enabled).To(BeTrue())
				} else {
					Expect(pool.Spec.IPIP).To(BeNil())
				}
			}
			Expect(foundv4Expected).To(BeTrue(),
				"Expected %s to be in Pools", expectedIPv4)
			Expect(foundv6Expected).To(BeTrue(),
				"Expected %s to be in Pools", expectedIPv6)
		},

		Entry("No env variables set", []EnvItem{},
			"192.168.0.0/16", "fd80:24e2:f998:72d6::/64", false),
		Entry("IPv4 Pool env var set",
			[]EnvItem{{"CALICO_IPV4POOL_CIDR", "172.16.0.0/24"}},
			"172.16.0.0/24", "fd80:24e2:f998:72d6::/64", false),
		Entry("IPv6 Pool env var set",
			[]EnvItem{{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"}},
			"192.168.0.0/16", "fdff:ffff:ffff:ffff:ffff::/80", false),
		Entry("Both IPv4 and IPv6 Pool env var set",
			[]EnvItem{
				{"CALICO_IPV4POOL_CIDR", "172.16.0.0/24"},
				{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"},
			},
			"172.16.0.0/24", "fdff:ffff:ffff:ffff:ffff::/80", false),
		Entry("CALICO_IPIP_ENABLED set false", []EnvItem{{"CALICO_IPIP_ENABLED", "false"}},
			"192.168.0.0/16", "fd80:24e2:f998:72d6::/64", false),
		Entry("CALICO_IPIP_ENABLED set true", []EnvItem{{"CALICO_IPIP_ENABLED", "true"}},
			"192.168.0.0/16", "fd80:24e2:f998:72d6::/64", true),
		Entry("IPv6 Pool and IPIP set",
			[]EnvItem{
				{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"},
				{"CALICO_IPIP_ENABLED", "true"},
			},
			"192.168.0.0/16", "fdff:ffff:ffff:ffff:ffff::/80", true),
	)

	Describe("Test NO_DEFAULT_POOLS env variable", func() {
		Context("Should have no pools defined", func() {

			// Erase etcd clean.
			testutils.CleanEtcd()

			// Create a new client.
			c, err := testutils.NewClient("")
			if err != nil {
				log.Println("Error creating client:", err)
			}

			// Set the env variables specified.
			os.Setenv("NO_DEFAULT_POOLS", "true")

			// Run the UUT.
			configureIPPools(c)

			// Get the IPPool list.
			poolList, err := c.IPPools().List(api.IPPoolMetadata{})
			It("should be able to access the IP pool list", func() {
				Expect(err).NotTo(HaveOccurred())
			})
			log.Println("Get pool list returns: ", poolList.Items)

			It("should have no IP pools", func() {
				Expect(poolList.Items).To(BeEmpty(), "Environment %#v", os.Environ())
			})
		})
	})

	Describe("Invalid Env Var combo", func() {
		exitCode = 0
		Context("Test termination", func() {
			oldExit := exitFunction
			exitFunction = fakeExitFunction
			defer func() { exitFunction = oldExit }()

			// Erase etcd clean.
			testutils.CleanEtcd()

			// Create a new client.
			c, err := testutils.NewClient("")
			if err != nil {
				log.Println("Error creating client:", err)
			}

			// Set combination of env vars expected to cause terminate.
			os.Setenv("NO_DEFAULT_POOLS", "true")
			os.Setenv("CALICO_IPV4POOL_CIDR", "172.16.0.0/16")

			// Run the UUT.
			configureIPPools(c)

			It("should have terminated", func() {
				Expect(exitCode).To(Equal(1))
			})
		})
	})

	Describe("Bad IP Pool value", func() {
		exitCode = 0
		oldExit := exitFunction
		exitFunction = fakeExitFunction
		defer func() { exitFunction = oldExit }()

		// Erase etcd clean.
		testutils.CleanEtcd()

		// Create a new client.
		c, err := testutils.NewClient("")
		if err != nil {
			log.Println("Error creating client:", err)
		}

		// Set bad IP Pool string.
		os.Setenv("CALICO_IPV4POOL_CIDR", "172.16.0.0a/16")

		// Run the UUT.
		configureIPPools(c)

		It("should have terminated", func() {
			Expect(exitCode).To(Equal(1))
		})
	})
})
