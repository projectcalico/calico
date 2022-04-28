// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package flannelmigration_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	fm "github.com/projectcalico/calico/kube-controllers/pkg/controllers/flannelmigration"
)

var _ = Describe("Config", func() {
	// unsetEnv() function that unsets environment variables.
	// required by flannel migration controller.
	unsetEnv := func() {
		os.Unsetenv("FLANNEL_DAEMONSET_NAME")
		os.Unsetenv("FLANNEL_SUBNET_LEN")
		os.Unsetenv("FLANNEL_ANNOTATION_PREFIX")
		os.Unsetenv("FLANNEL_VNI")
		os.Unsetenv("FLANNEL_PORT")
		os.Unsetenv("CALICO_DAMONSET_NAME")
		os.Unsetenv("CNI_CONFIG_DIR")
		os.Unsetenv("POD_NODE_NAME")
		os.Unsetenv("FLANNEL_SUBNET_ENV")
	}

	// setEnv() function that sets environment variables.
	setEnv := func() {
		os.Setenv("FLANNEL_DAEMONSET_NAME", "flannel-daemonset")
		os.Setenv("FLANNEL_SUBNET_LEN", "25")
		os.Setenv("FLANNEL_ANNOTATION_PREFIX", "flannel-prefix")
		os.Setenv("FLANNEL_VNI", "3")
		os.Setenv("FLANNEL_PORT", "1234")
		os.Setenv("CALICO_DAEMONSET_NAME", "calico-daemonset")
		os.Setenv("CNI_CONFIG_DIR", "/cni/config")
		os.Setenv("POD_NODE_NAME", "test-node")
		os.Setenv("FLANNEL_SUBNET_ENV", "FLANNEL_NETWORK=10.244.0.0/16;FLANNEL_SUBNET=10.244.1.1/24;FLANNEL_MTU=8951;FLANNEL_IPMASQ=false;")
	}

	// setWrongEnv() function sets environment variables
	// with values of wrong data type
	setWrongEnv := func() {
		os.Setenv("FLANNEL_VNI", "somestring")
	}

	It("default values without POD_NODE_NAME", func() {
		// Parse config
		config := new(fm.Config)
		err := config.Parse()
		Expect(err).Should(HaveOccurred())
	})

	It("default values with POD_NODE_NAME", func() {
		os.Setenv("POD_NODE_NAME", "test-node")
		defer unsetEnv()

		// Parse config
		config := new(fm.Config)
		err := config.Parse()
		Expect(err).ShouldNot(HaveOccurred())

		// Assert default values
		Expect(config.FlannelNetwork).To(Equal(""))
		Expect(config.FlannelMTU).To(Equal(0))
		Expect(config.FlannelIPMasq).To(Equal(true))
		Expect(config.FlannelDaemonsetName).To(Equal("kube-flannel-ds-amd64"))
		Expect(config.FlannelSubnetLen).To(Equal(24))
		Expect(config.FlannelAnnotationPrefix).To(Equal("flannel.alpha.coreos.com"))
		Expect(config.FlannelVNI).To(Equal(1))
		Expect(config.FlannelPort).To(Equal(8472))
		Expect(config.CalicoDaemonsetName).To(Equal("calico-node"))
		Expect(config.CniConfigDir).To(Equal("/etc/cni/net.d"))
		Expect(config.PodNodeName).To(Equal("test-node"))
		Expect(config.FlannelSubnetEnv).To(Equal(""))
	})

	It("with valid user defined values", func() {
		// Set environment variables
		setEnv()
		defer unsetEnv()

		// Parse config
		config := new(fm.Config)
		err := config.Parse()
		Expect(err).NotTo(HaveOccurred())

		// Assert values
		Expect(config.FlannelNetwork).To(Equal("10.244.0.0/16"))
		Expect(config.FlannelMTU).To(Equal(8951))
		Expect(config.FlannelIPMasq).To(Equal(false))
		Expect(config.FlannelDaemonsetName).To(Equal("flannel-daemonset"))
		Expect(config.FlannelSubnetLen).To(Equal(25))
		Expect(config.FlannelAnnotationPrefix).To(Equal("flannel-prefix"))
		Expect(config.FlannelVNI).To(Equal(3))
		Expect(config.FlannelPort).To(Equal(1234))
		Expect(config.CalicoDaemonsetName).To(Equal("calico-daemonset"))
		Expect(config.CniConfigDir).To(Equal("/cni/config"))
		Expect(config.PodNodeName).To(Equal("test-node"))
	})

	It("with invalid user defined values", func() {

		// Set wrong environment variables
		setWrongEnv()
		defer unsetEnv()

		// Parse config
		config := new(fm.Config)
		err := config.Parse()
		Expect(err).To(HaveOccurred())
	})
})
