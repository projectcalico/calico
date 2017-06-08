// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	. "github.com/projectcalico/felix/config"

	"net"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Config parsing",
	func(key, value string, expected interface{}, errorExpected ...bool) {
		config := New()
		config.UpdateFrom(map[string]string{key: value},
			EnvironmentVariable)
		configPtr := reflect.ValueOf(config)
		configElem := configPtr.Elem()
		fieldRef := configElem.FieldByName(key)
		newVal := fieldRef.Interface()
		Expect(newVal).To(Equal(expected))
		if len(errorExpected) > 0 && errorExpected[0] {
			Expect(config.Err).To(HaveOccurred())
		} else {
			Expect(config.Err).NotTo(HaveOccurred())
		}
	},

	Entry("FelixHostname", "FelixHostname", "hostname", "hostname"),
	Entry("FelixHostname FQDN", "FelixHostname", "hostname.foo.bar.com", "hostname.foo.bar.com"),
	Entry("FelixHostname as IP", "FelixHostname", "1.2.3.4", "1.2.3.4"),

	Entry("EtcdAddr IP", "EtcdAddr", "10.0.0.1:1234", "10.0.0.1:1234"),
	Entry("EtcdAddr Empty", "EtcdAddr", "", "127.0.0.1:2379"),
	Entry("EtcdAddr host", "EtcdAddr", "host:1234", "host:1234"),
	Entry("EtcdScheme", "EtcdScheme", "https", "https"),

	// Etcd key files will be tested for existence, skipping for now.

	Entry("EtcdEndpoints HTTP", "EtcdEndpoints",
		"http://127.0.0.1:1234, http://host:2345",
		[]string{"http://127.0.0.1:1234/", "http://host:2345/"}),
	Entry("EtcdEndpoints HTTPS", "EtcdEndpoints",
		"https://127.0.0.1:1234/, https://host:2345",
		[]string{"https://127.0.0.1:1234/", "https://host:2345/"}),

	Entry("TyphaAddr empty", "TyphaAddr", "", ""),
	Entry("TyphaAddr set", "TyphaAddr", "foo:1234", "foo:1234"),
	Entry("TyphaK8sServiceName empty", "TyphaK8sServiceName", "", ""),
	Entry("TyphaK8sServiceName set", "TyphaK8sServiceName", "calico-typha", "calico-typha"),
	Entry("TyphaK8sNamespace empty", "TyphaK8sNamespace", "", "kube-system"),
	Entry("TyphaK8sNamespace set", "TyphaK8sNamespace", "default", "default"),
	Entry("TyphaK8sNamespace none", "TyphaK8sNamespace", "none", "kube-system", true),

	Entry("InterfacePrefix", "InterfacePrefix", "tap", "tap"),
	Entry("InterfacePrefix list", "InterfacePrefix", "tap,cali", "tap,cali"),

	Entry("ChainInsertMode append", "ChainInsertMode", "append", "append"),

	Entry("IptablesPostWriteCheckIntervalSecs", "IptablesPostWriteCheckIntervalSecs",
		"1.5", 1500*time.Millisecond),

	Entry("DefaultEndpointToHostAction", "DefaultEndpointToHostAction",
		"RETURN", "RETURN"),
	Entry("DefaultEndpointToHostAction", "DefaultEndpointToHostAction",
		"ACCEPT", "ACCEPT"),

	Entry("LogFilePath", "LogFilePath", "/tmp/felix.log", "/tmp/felix.log"),

	Entry("LogSeverityFile", "LogSeverityFile", "debug", "DEBUG"),
	Entry("LogSeverityFile", "LogSeverityFile", "warning", "WARNING"),
	Entry("LogSeverityFile", "LogSeverityFile", "error", "ERROR"),
	Entry("LogSeverityFile", "LogSeverityFile", "critical", "CRITICAL"),

	Entry("LogSeverityScreen", "LogSeverityScreen", "debug", "DEBUG"),
	Entry("LogSeverityScreen", "LogSeverityScreen", "warning", "WARNING"),
	Entry("LogSeverityScreen", "LogSeverityScreen", "error", "ERROR"),
	Entry("LogSeverityScreen", "LogSeverityScreen", "critical", "CRITICAL"),

	Entry("LogSeveritySys", "LogSeveritySys", "debug", "DEBUG"),
	Entry("LogSeveritySys", "LogSeveritySys", "warning", "WARNING"),
	Entry("LogSeveritySys", "LogSeveritySys", "error", "ERROR"),
	Entry("LogSeveritySys", "LogSeveritySys", "critical", "CRITICAL"),

	Entry("IpInIpEnabled", "IpInIpEnabled", "true", true),
	Entry("IpInIpEnabled", "IpInIpEnabled", "y", true),
	Entry("IpInIpEnabled", "IpInIpEnabled", "True", true),

	Entry("IpInIpMtu", "IpInIpMtu", "1234", int(1234)),
	Entry("IpInIpTunnelAddr", "IpInIpTunnelAddr",
		"10.0.0.1", net.ParseIP("10.0.0.1")),

	Entry("ReportingIntervalSecs", "ReportingIntervalSecs", "31", 31*time.Second),
	Entry("ReportingTTLSecs", "ReportingTTLSecs", "91", 91*time.Second),

	Entry("EndpointReportingEnabled", "EndpointReportingEnabled",
		"true", true),
	Entry("EndpointReportingEnabled", "EndpointReportingEnabled",
		"yes", true),
	Entry("EndpointReportingDelaySecs", "EndpointReportingDelaySecs",
		"10", 10*time.Second),

	Entry("MaxIpsetSize", "MaxIpsetSize", "12345", int(12345)),
	Entry("IptablesMarkMask", "IptablesMarkMask", "0xf0f0", uint32(0xf0f0)),

	Entry("PrometheusMetricsEnabled", "PrometheusMetricsEnabled", "true", true),
	Entry("PrometheusMetricsPort", "PrometheusMetricsPort", "1234", int(1234)),
	Entry("PrometheusGoMetricsEnabled", "PrometheusGoMetricsEnabled", "false", false),
	Entry("PrometheusProcessMetricsEnabled", "PrometheusProcessMetricsEnabled", "false", false),

	Entry("FailsafeInboundHostPorts old syntax", "FailsafeInboundHostPorts", "1,2,3,4",
		[]ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Protocol: "tcp", Port: 2},
			{Protocol: "tcp", Port: 3},
			{Protocol: "tcp", Port: 4},
		}),
	Entry("FailsafeOutboundHostPorts old syntax", "FailsafeOutboundHostPorts", "1,2,3,4",
		[]ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Protocol: "tcp", Port: 2},
			{Protocol: "tcp", Port: 3},
			{Protocol: "tcp", Port: 4},
		}),
	Entry("FailsafeInboundHostPorts new syntax", "FailsafeInboundHostPorts", "tcp:1,udp:2",
		[]ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeOutboundHostPorts new syntax", "FailsafeOutboundHostPorts", "tcp:1,udp:2",
		[]ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeInboundHostPorts mixed syntax", "FailsafeInboundHostPorts", "1,udp:2",
		[]ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeOutboundHostPorts mixed syntax", "FailsafeOutboundHostPorts", "1,udp:2",
		[]ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Protocol: "udp", Port: 2},
		}),

	Entry("FailsafeInboundHostPorts bad syntax -> defaulted", "FailsafeInboundHostPorts", "foo:1",
		[]ProtoPort{
			{Protocol: "tcp", Port: 22},
			{Protocol: "udp", Port: 68},
		},
		true,
	),
	Entry("FailsafeInboundHostPorts too many parts -> defaulted", "FailsafeInboundHostPorts", "tcp:1:bar",
		[]ProtoPort{
			{Protocol: "tcp", Port: 22},
			{Protocol: "udp", Port: 68},
		},
		true,
	),

	Entry("FailsafeInboundHostPorts none", "FailsafeInboundHostPorts", "none", []ProtoPort(nil)),
	Entry("FailsafeOutboundHostPorts none", "FailsafeOutboundHostPorts", "none", []ProtoPort(nil)),

	Entry("FailsafeInboundHostPorts empty", "FailsafeInboundHostPorts", "",
		[]ProtoPort{
			{Protocol: "tcp", Port: 22},
			{Protocol: "udp", Port: 68},
		},
	),
	Entry("FailsafeOutboundHostPorts empty", "FailsafeOutboundHostPorts", "",
		[]ProtoPort{
			{Protocol: "tcp", Port: 2379},
			{Protocol: "tcp", Port: 2380},
			{Protocol: "tcp", Port: 4001},
			{Protocol: "tcp", Port: 7001},
			{Protocol: "udp", Port: 53},
			{Protocol: "udp", Port: 67},
		},
	),
)

var _ = DescribeTable("Mark bit calculation tests",
	func(mask string, bitNum int, expected uint32) {
		config := New()
		config.UpdateFrom(map[string]string{"IptablesMarkMask": mask}, EnvironmentVariable)
		Expect(config.NthIPTablesMark(bitNum)).To(Equal(expected))
	},
	Entry("0th bit in 0xf", "0xf", 0, uint32(0x1)),
	Entry("1st bit in 0xf", "0xf", 1, uint32(0x2)),
	Entry("7th bit in 0xff", "0xff", 7, uint32(0x80)),
	Entry("4th bit in 0xf00f", "0xf00f", 4, uint32(0x1000)),
	Entry("3rd bit in 0xf00f", "0xf00f", 3, uint32(0x0008)),
	Entry("7th bit in 0xf00f", "0xf00f", 7, uint32(0x8000)),
	Entry("0th bit of 0xff000000", "0xff000000", 0, uint32(0x01000000)),
)

var _ = DescribeTable("Next mark bit calculation tests",
	func(mask string, numCalls int, expected uint32) {
		config := New()
		config.UpdateFrom(map[string]string{"IptablesMarkMask": mask}, EnvironmentVariable)
		var mark uint32
		for i := 0; i < numCalls; i++ {
			mark = config.NextIptablesMark()
		}
		Expect(mark).To(Equal(expected))
	},
	Entry("0th bit in 0xf", "0xf", 1, uint32(0x1)),
	Entry("1st bit in 0xf", "0xf", 2, uint32(0x2)),
	Entry("7th bit in 0xff", "0xff", 8, uint32(0x80)),
	Entry("7th bit in 0xf00f", "0xf00f", 8, uint32(0x8000)),
	Entry("0th bit of 0xff000000", "0xff000000", 1, uint32(0x01000000)),
)

var _ = Describe("DatastoreConfig tests", func() {
	var c *Config
	Describe("with IPIP enabled", func() {
		BeforeEach(func() {
			c = New()
			c.DatastoreType = "k8s"
			c.IpInIpEnabled = true
		})
		It("should leave node polling enabled", func() {
			Expect(c.DatastoreConfig().Spec.K8sDisableNodePoll).To(BeFalse())
		})
	})
	Describe("with IPIP disabled", func() {
		BeforeEach(func() {
			c = New()
			c.DatastoreType = "k8s"
			c.IpInIpEnabled = false
		})
		It("should leave node polling enabled", func() {
			Expect(c.DatastoreConfig().Spec.K8sDisableNodePoll).To(BeTrue())
		})
	})
})
