// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

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

package common

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var nilSlice []int
var nilMap map[string]string

var _ = DescribeTable("Testing joinAndTruncate",
	func(items interface{}, separator string, maxLength int, expected string) {
		result := joinAndTruncate(items, separator, maxLength)
		Expect(result).To(Equal(expected))
	},
	Entry("nil interface", interface{}(nil), ",", 0, ""),
	Entry("nil map", nilMap, ",", 0, ""),
	Entry("empty map", make(map[string]string), ",", 0, ""),
	Entry("map with one kv", map[string]string{"a": "b"}, ",", 0, "a=b"),
	Entry("map with several kv", map[string]string{"a": "b", "b": "c", "go": "gopher"}, ",", 0, "a=b,b=c,go=gopher"),
	Entry("map with several kv, truncate", map[string]string{"giraffe": "praying mantis", "bird": "felix", "go": "gopher", "elephant": "hippo"}, ",", 15,
		"bird=felix,e..."),
	Entry("map with non string", map[string]int{"a": 1}, ",", 0, "a=1"),
	Entry("map with non string", map[string]int{"a": -1}, ",", 0, "a=-1"),
	Entry("map with non string", map[int]int{123: 1}, ",", 0, "123=1"),
	Entry("map with non string, truncated", map[int]int{123: 4567}, ",", 3, "..."),

	Entry("nil slice", nilSlice, ",", 0, ""),
	Entry("empty slice", []int{}, ",", 0, ""),
	Entry("slice with one value", []int{1}, ",", 0, "1"),
	Entry("slice with multiple value", []string{"one", "two", "three", "four"}, ",", 0, "one,two,three,four"),
	Entry("slice with multiple value different separator", []string{"one", "two", "three", "four"}, "-", 0, "one-two-three-four"),
	Entry("slice with multiple value, truncate", []string{"otorhinolaryngological", "psychophysicotherapeutics", "hepaticocholangiogastrostomy"}, ",", 10,
		"otorhin..."),
	Entry("slice truncate", []int{12345, 67890}, ",", 6, "123..."),
	Entry("slice truncate", []int{1234567}, ",", 6, "123..."),
	Entry("slice no truncate", []int{123456}, ",", 6, "123456"),
	Entry("string", "HelloWorld", ",", 0, "HelloWorld"),
)

var _ = Describe("Testing printer config()", func() {
	var client *mockClient
	BeforeEach(func() {
		client = newMockClient()
	})

	It("prints the default asnumber 64512 when BGPConfig.Spec.ASNumber is nil", func() {
		Expect(config(client)("asnumber")).To(Equal("64512"))
	})

	It("prints the default asnumber 64512 when the default BGPConfig cannot be found", func() {
		client.bgpConfig = nil
		Expect(config(client)("asnumber")).To(Equal("64512"))
	})

	It("prints the asnumber from BGPConfig.Spec.ASNumber when it is present", func() {
		asNumber := numorstring.ASNumber(12345)
		bgpConfig := apiv3.BGPConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default", ResourceVersion: "1234",
				CreationTimestamp: metav1.Now(),
				UID:               "test-printer-bgpconfig",
			},
			Spec: apiv3.BGPConfigurationSpec{
				ASNumber: &asNumber,
			},
		}
		_, _ = client.BGPConfigurations().Update(context.Background(), &bgpConfig, options.SetOptions{})
		Expect(config(client)("asnumber")).To(Equal(asNumber.String()))
	})

	It("prints 'unknown' when there is an error getting the default BGPConfig", func() {
		client.throwError = true
		Expect(config(client)("asnumber")).To(Equal("unknown"))
	})
})

type mockClient struct {
	clientv3.Interface
	clientv3.BGPConfigurationInterface
	bgpConfig  *apiv3.BGPConfiguration
	throwError bool
}

func newMockClient() *mockClient {
	return &mockClient{
		bgpConfig: &apiv3.BGPConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default", ResourceVersion: "1234",
				CreationTimestamp: metav1.Now(),
				UID:               "test-printer-bgpconfig",
			},
			Spec: apiv3.BGPConfigurationSpec{},
		},
		throwError: false,
	}
}

func (c *mockClient) BGPConfigurations() clientv3.BGPConfigurationInterface {
	return c
}

func (c *mockClient) Get(_ context.Context, name string, _ options.GetOptions) (*apiv3.BGPConfiguration, error) {
	if c.throwError {
		return nil, errors.New("mock error for testing")
	}

	if c.bgpConfig == nil {
		return nil, cerrors.ErrorResourceDoesNotExist{}

	}

	return c.bgpConfig, nil
}

func (c *mockClient) Update(_ context.Context, res *apiv3.BGPConfiguration, _ options.SetOptions) (*apiv3.BGPConfiguration, error) {
	c.bgpConfig = res
	return c.bgpConfig, nil
}
