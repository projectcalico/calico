// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.

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
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("FelixConfig vs ConfigParams parity", func() {
	var fcFields map[string]reflect.StructField
	var cpFields map[string]reflect.StructField
	cpFieldsToIgnore := []string{
		"sourceToRawConfig",
		"rawValues",
		"Err",
		"numIptablesBitsAllocated",

		// Moved to ClusterInformation
		"ClusterGUID",
		"ClusterType",
		"CalicoVersion",
		"Variant",

		// Moved to Node.
		"IpInIpTunnelAddr",
		"IPv4VXLANTunnelAddr",
		"IPv6VXLANTunnelAddr",
		"VXLANTunnelMACAddr",
		"VXLANTunnelMACAddrV6",
		"loadClientConfigFromEnvironment",

		"loadClientConfigFromEnvironment",
		"useNodeResourceUpdates",
		"internalOverrides",

		// Temporary field to implement and test IPv6 in BPF dataplane
		"BpfIpv6Support",
	}
	cpFieldNameToFC := map[string]string{
		"IpInIpEnabled":                      "IPIPEnabled",
		"VXLANEnabled":                       "VXLANEnabled",
		"IpInIpMtu":                          "IPIPMTU",
		"Ipv6Support":                        "IPv6Support",
		"IptablesLockProbeIntervalMillis":    "IptablesLockProbeInterval",
		"IptablesPostWriteCheckIntervalSecs": "IptablesPostWriteCheckInterval",
		"NetlinkTimeoutSecs":                 "NetlinkTimeout",
		"ReportingIntervalSecs":              "ReportingInterval",
		"ReportingTTLSecs":                   "ReportingTTL",
		"UsageReportingInitialDelaySecs":     "UsageReportingInitialDelay",
		"UsageReportingIntervalSecs":         "UsageReportingInterval",
		"EndpointReportingDelaySecs":         "EndpointReportingDelay",
	}
	fcFieldNameToCP := map[string]string{}
	for k, v := range cpFieldNameToFC {
		fcFieldNameToCP[v] = k
	}

	BeforeEach(func() {
		fcFields = fieldsByName(v3.FelixConfigurationSpec{})

		cpFields = fieldsByName(config.Config{})
		for _, name := range cpFieldsToIgnore {
			delete(cpFields, name)
		}
	})

	It("FelixConfigurationSpec should contain all Config fields", func() {
		for n, f := range cpFields {
			mappedName := cpFieldNameToFC[n]
			if mappedName != "" {
				n = mappedName
			}
			if strings.HasPrefix(n, "Debug") {
				continue
			}
			if strings.Contains(string(f.Tag), "local") {
				continue
			}
			if n == "Encapsulation" {
				continue
			}
			Expect(fcFields).To(HaveKey(n))
		}
	})
	It("Config should contain all FelixConfigurationSpec fields", func() {
		for n := range fcFields {
			mappedName := fcFieldNameToCP[n]
			if mappedName != "" {
				n = mappedName
			}
			Expect(cpFields).To(HaveKey(n))
		}
	})
})

func fieldsByName(example interface{}) map[string]reflect.StructField {
	fields := map[string]reflect.StructField{}
	t := reflect.TypeOf(example)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fields[f.Name] = f
	}
	return fields
}

var _ = Describe("Config override empty", func() {
	var cp *config.Config
	BeforeEach(func() {
		cp = config.New()
	})

	It("should allow config override", func() {
		changed, err := cp.OverrideParam("BPFEnabled", "true")
		Expect(changed).To(BeTrue())
		Expect(err).NotTo(HaveOccurred())
		Expect(cp.BPFEnabled).To(BeTrue())
	})

	Describe("with a param set", func() {
		BeforeEach(func() {
			_, err := cp.UpdateFrom(map[string]string{"BPFEnabled": "true"}, config.DatastorePerHost)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should allow config override", func() {
			By("Having correct initial value")
			Expect(cp.BPFEnabled).To(BeTrue())

			By("Having correct value after override")
			changed, err := cp.OverrideParam("BPFEnabled", "false")
			Expect(changed).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
			Expect(cp.BPFEnabled).To(BeFalse())

			By("Ignoring a lower-priority config update")
			// Env vars get converted to lower-case before calling UpdateFrom.
			changed, err = cp.UpdateFrom(map[string]string{"bpfenabled": "true"}, config.EnvironmentVariable)
			Expect(changed).To(BeFalse())
			Expect(err).NotTo(HaveOccurred())
			Expect(cp.BPFEnabled).To(BeFalse())
		})
	})

	Describe("with env var set", func() {
		BeforeEach(func() {
			// Env vars get converted to lower-case before calling UpdateFrom.
			changed, err := cp.UpdateFrom(map[string]string{"bpfenabled": "true"}, config.EnvironmentVariable)
			Expect(changed).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
			Expect(cp.BPFEnabled).To(BeTrue())
		})

		It("should be overridable", func() {
			changed, err := cp.OverrideParam("BPFEnabled", "false")
			Expect(changed).To(BeTrue())
			Expect(err).ToNot(HaveOccurred())
			Expect(cp.BPFEnabled).To(BeFalse())
		})
	})

	It("should have correct initial IptablesBackend value 'auto'", func() {
		Expect(cp.IptablesBackend).To(Equal("auto"))
	})

	It("should allow IptablesBackend value 'Auto' read from FelixConfiguration resource", func() {
		changed, err := cp.UpdateFrom(map[string]string{"IptablesBackend": "Auto"}, config.DatastorePerHost)
		Expect(changed).To(BeFalse()) // auto is the default.
		Expect(err).NotTo(HaveOccurred())
		Expect(cp.IptablesBackend).To(Equal("auto"))
	})
})

var (
	nilServerPortSlice []config.ServerPort
	t                  bool = true
)

var _ = DescribeTable("Config parsing",
	func(key, value string, expected interface{}, errorExpected ...bool) {
		cfg := config.New()
		_, err := cfg.UpdateFrom(map[string]string{key: value}, config.EnvironmentVariable)
		configPtr := reflect.ValueOf(cfg)
		configElem := configPtr.Elem()
		fieldRef := configElem.FieldByName(key)
		newVal := fieldRef.Interface()
		Expect(newVal).To(Equal(expected), fmt.Sprintf("Expected %s=%q to parse as %v but got %v", key, value, expected, newVal))
		if len(errorExpected) > 0 && errorExpected[0] {
			Expect(err).To(HaveOccurred(), fmt.Sprintf("Expected an error when setting %s=%q", key, value))
			Expect(cfg.Err).To(HaveOccurred(), fmt.Sprintf("Expected an error to be stored when setting %s=%q", key, value))
		} else {
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Expected no error when setting %s=%q", key, value))
			Expect(cfg.Err).NotTo(HaveOccurred(), fmt.Sprintf("Expected no error to be stored when setting %s=%q", key, value))
		}
	},

	Entry("Netlink Timeout - default value", "NetlinkTimeoutSecs", "", time.Duration(10*time.Second), false),

	Entry("EndpointStatusPathPrefix - default value", "EndpointStatusPathPrefix", "", "/var/run/calico", false),

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

	Entry("InterfaceExclude one value no regexp", "InterfaceExclude", "kube-ipvs0", []*regexp.Regexp{
		regexp.MustCompile("^kube-ipvs0$"),
	}),
	Entry("InterfaceExclude list no regexp", "InterfaceExclude", "kube-ipvs0,dummy", []*regexp.Regexp{
		regexp.MustCompile("^kube-ipvs0$"),
		regexp.MustCompile("^dummy$"),
	}),
	Entry("InterfaceExclude one value regexp", "InterfaceExclude", "/kube-ipvs/", []*regexp.Regexp{
		regexp.MustCompile("kube-ipvs"),
	}),
	Entry("InterfaceExclude list regexp", "InterfaceExclude", "kube-ipvs0,dummy,/^veth.*$/", []*regexp.Regexp{
		regexp.MustCompile("^kube-ipvs0$"),
		regexp.MustCompile("^dummy$"),
		regexp.MustCompile("^veth.*$"),
	}),
	Entry("InterfaceExclude no regexp", "InterfaceExclude", "/^kube.*/,/veth/", []*regexp.Regexp{
		regexp.MustCompile("^kube.*"),
		regexp.MustCompile("veth"),
	}),
	Entry("InterfaceExclude list empty regexp", "InterfaceExclude", "kube,//", []*regexp.Regexp{
		regexp.MustCompile("^kube-ipvs0$"),
	}),
	Entry("InterfaceExclude list bad comma use", "InterfaceExclude", "/kube,/,dummy", []*regexp.Regexp{
		regexp.MustCompile("^kube-ipvs0$"),
	}),
	Entry("InterfaceExclude list invalid regexp symbol", "InterfaceExclude", `/^kube\K/`, []*regexp.Regexp{
		regexp.MustCompile("^kube-ipvs0$"),
	}),

	Entry("ChainInsertMode append", "ChainInsertMode", "append", "append"),
	Entry("ChainInsertMode append", "ChainInsertMode", "Append", "append"),

	Entry("IptablesPostWriteCheckIntervalSecs", "IptablesPostWriteCheckIntervalSecs",
		"1.5", 1500*time.Millisecond),
	Entry("IptablesLockProbeIntervalMillis", "IptablesLockProbeIntervalMillis",
		"123", 123*time.Millisecond),
	Entry("IptablesLockProbeIntervalMillis garbage", "IptablesLockProbeIntervalMillis",
		"garbage", 50*time.Millisecond),

	Entry("DefaultEndpointToHostAction", "DefaultEndpointToHostAction",
		"RETURN", "RETURN"),
	Entry("DefaultEndpointToHostAction", "DefaultEndpointToHostAction",
		"ACCEPT", "ACCEPT"),

	Entry("IptablesFilterAllowAction", "IptablesFilterAllowAction",
		"RETURN", "RETURN"),
	Entry("IptablesMangleAllowAction", "IptablesMangleAllowAction",
		"RETURN", "RETURN"),

	Entry("IptablesFilterDenyAction", "IptablesFilterDenyAction", "DROP", "DROP"),
	Entry("IptablesFilterDenyAction", "IptablesFilterDenyAction", "REJECT", "REJECT"),

	Entry("LogFilePath", "LogFilePath", "/tmp/felix.log", "/tmp/felix.log"),

	Entry("LogSeverityFile", "LogSeverityFile", "debug", "DEBUG"),
	Entry("LogSeverityFile", "LogSeverityFile", "warning", "WARNING"),
	Entry("LogSeverityFile", "LogSeverityFile", "error", "ERROR"),
	Entry("LogSeverityFile", "LogSeverityFile", "fatal", "FATAL"),

	Entry("LogSeverityScreen", "LogSeverityScreen", "debug", "DEBUG"),
	Entry("LogSeverityScreen", "LogSeverityScreen", "warning", "WARNING"),
	Entry("LogSeverityScreen", "LogSeverityScreen", "error", "ERROR"),
	Entry("LogSeverityScreen", "LogSeverityScreen", "fatal", "FATAL"),

	Entry("LogSeveritySys", "LogSeveritySys", "debug", "DEBUG"),
	Entry("LogSeveritySys", "LogSeveritySys", "warning", "WARNING"),
	Entry("LogSeveritySys", "LogSeveritySys", "error", "ERROR"),
	Entry("LogSeveritySys", "LogSeveritySys", "fatal", "FATAL"),

	Entry("LogDebugFilenameRegex", "LogDebugFilenameRegex", "", (*regexp.Regexp)(nil)),
	Entry("LogDebugFilenameRegex", "LogDebugFilenameRegex", ".*", regexp.MustCompile(".*")),

	Entry("IpInIpEnabled", "IpInIpEnabled", "true", &t),
	Entry("IpInIpEnabled", "IpInIpEnabled", "y", &t),
	Entry("IpInIpEnabled", "IpInIpEnabled", "True", &t),

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

	Entry("HealthEnabled", "HealthEnabled", "true", true),
	Entry("HealthHost", "HealthHost", "127.0.0.1", "127.0.0.1"),
	Entry("HealthPort", "HealthPort", "1234", int(1234)),

	Entry("PrometheusMetricsEnabled", "PrometheusMetricsEnabled", "true", true),
	Entry("PrometheusMetricsHost", "PrometheusMetricsHost", "10.0.0.1", "10.0.0.1"),
	Entry("PrometheusMetricsPort", "PrometheusMetricsPort", "1234", int(1234)),
	Entry("PrometheusGoMetricsEnabled", "PrometheusGoMetricsEnabled", "false", false),
	Entry("PrometheusProcessMetricsEnabled", "PrometheusProcessMetricsEnabled", "false", false),

	Entry("FailsafeInboundHostPorts old syntax", "FailsafeInboundHostPorts", "1,2,3,4",
		[]config.ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Protocol: "tcp", Port: 2},
			{Protocol: "tcp", Port: 3},
			{Protocol: "tcp", Port: 4},
		}),
	Entry("FailsafeOutboundHostPorts old syntax", "FailsafeOutboundHostPorts", "1,2,3,4",
		[]config.ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Protocol: "tcp", Port: 2},
			{Protocol: "tcp", Port: 3},
			{Protocol: "tcp", Port: 4},
		}),
	Entry("FailsafeInboundHostPorts new syntax", "FailsafeInboundHostPorts", "tcp:1,udp:2",
		[]config.ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeOutboundHostPorts new syntax", "FailsafeOutboundHostPorts", "tcp:1,udp:2",
		[]config.ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeInboundHostPorts new cidr syntax", "FailsafeInboundHostPorts", "tcp:0.0.0.0/0:1,udp:0.0.0.0/0:2",
		[]config.ProtoPort{
			{Net: "0.0.0.0/0", Protocol: "tcp", Port: 1},
			{Net: "0.0.0.0/0", Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeOutboundHostPorts new cidr syntax", "FailsafeOutboundHostPorts", "tcp:0.0.0.0/0:1,udp:0.0.0.0/0:2",
		[]config.ProtoPort{
			{Net: "0.0.0.0/0", Protocol: "tcp", Port: 1},
			{Net: "0.0.0.0/0", Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeInboundHostPorts new cidr syntax IPv6", "FailsafeInboundHostPorts", "tcp:[::/0]:1,udp:[::/0]:2",
		[]config.ProtoPort{
			{Net: "::/0", Protocol: "tcp", Port: 1},
			{Net: "::/0", Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeOutboundHostPorts new cidr syntax IPv6", "FailsafeOutboundHostPorts", "tcp:[::/0]:1,udp:[::/0]:2",
		[]config.ProtoPort{
			{Net: "::/0", Protocol: "tcp", Port: 1},
			{Net: "::/0", Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeInboundHostPorts mixed syntax", "FailsafeInboundHostPorts", "1,udp:2",
		[]config.ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeOutboundHostPorts mixed syntax", "FailsafeOutboundHostPorts", "1,udp:2",
		[]config.ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeInboundHostPorts new mixed syntax", "FailsafeInboundHostPorts", "1,udp:0.0.0.0/0:2",
		[]config.ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Net: "0.0.0.0/0", Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeOutboundHostPorts new mixed syntax", "FailsafeOutboundHostPorts", "1,udp:0.0.0.0/0:2",
		[]config.ProtoPort{
			{Protocol: "tcp", Port: 1},
			{Net: "0.0.0.0/0", Protocol: "udp", Port: 2},
		}),
	Entry("FailsafeInboundHostPorts bad syntax -> defaulted", "FailsafeInboundHostPorts", "foo:1",
		[]config.ProtoPort{
			{Protocol: "tcp", Port: 22},
			{Protocol: "udp", Port: 68},
			{Protocol: "tcp", Port: 179},
			{Protocol: "tcp", Port: 2379},
			{Protocol: "tcp", Port: 2380},
			{Protocol: "tcp", Port: 5473},
			{Protocol: "tcp", Port: 6443},
			{Protocol: "tcp", Port: 6666},
			{Protocol: "tcp", Port: 6667},
		},
		true,
	),
	Entry("FailsafeInboundHostPorts too many parts -> defaulted", "FailsafeInboundHostPorts", "tcp:0.0.0.0/0:1:bar",
		[]config.ProtoPort{
			{Protocol: "tcp", Port: 22},
			{Protocol: "udp", Port: 68},
			{Protocol: "tcp", Port: 179},
			{Protocol: "tcp", Port: 2379},
			{Protocol: "tcp", Port: 2380},
			{Protocol: "tcp", Port: 5473},
			{Protocol: "tcp", Port: 6443},
			{Protocol: "tcp", Port: 6666},
			{Protocol: "tcp", Port: 6667},
		},
		true,
	),

	Entry("FailsafeInboundHostPorts none", "FailsafeInboundHostPorts", "none", []config.ProtoPort(nil)),
	Entry("FailsafeOutboundHostPorts none", "FailsafeOutboundHostPorts", "none", []config.ProtoPort(nil)),

	Entry("FailsafeInboundHostPorts empty", "FailsafeInboundHostPorts", "",
		[]config.ProtoPort{
			{Protocol: "tcp", Port: 22},
			{Protocol: "udp", Port: 68},
			{Protocol: "tcp", Port: 179},
			{Protocol: "tcp", Port: 2379},
			{Protocol: "tcp", Port: 2380},
			{Protocol: "tcp", Port: 5473},
			{Protocol: "tcp", Port: 6443},
			{Protocol: "tcp", Port: 6666},
			{Protocol: "tcp", Port: 6667},
		},
	),
	Entry("FailsafeOutboundHostPorts empty", "FailsafeOutboundHostPorts", "",
		[]config.ProtoPort{
			{Protocol: "udp", Port: 53},
			{Protocol: "udp", Port: 67},
			{Protocol: "tcp", Port: 179},
			{Protocol: "tcp", Port: 2379},
			{Protocol: "tcp", Port: 2380},
			{Protocol: "tcp", Port: 5473},
			{Protocol: "tcp", Port: 6443},
			{Protocol: "tcp", Port: 6666},
			{Protocol: "tcp", Port: 6667},
		},
	),

	Entry("GoMaxProcs default", "GoMaxProcs", "", -1),
	Entry("GoMaxProcs -2 should be replaced with default", "GoMaxProcs", "-2", -1),
	Entry("GoMaxProcs 1000 valid", "GoMaxProcs", "1000", 1000),

	Entry("KubeNodePortRanges empty", "KubeNodePortRanges", "",
		[]numorstring.Port{
			{MinPort: 30000, MaxPort: 32767, PortName: ""},
		},
	),
	Entry("KubeNodePortRanges range", "KubeNodePortRanges", "30001:30002,30030:30040,30500:30600",
		[]numorstring.Port{
			{MinPort: 30001, MaxPort: 30002, PortName: ""},
			{MinPort: 30030, MaxPort: 30040, PortName: ""},
			{MinPort: 30500, MaxPort: 30600, PortName: ""},
		},
	),

	Entry("IptablesNATOutgoingInterfaceFilter", "IptablesNATOutgoingInterfaceFilter", "cali-123", "cali-123"),
	Entry("IptablesNATOutgoingInterfaceFilter", "IptablesNATOutgoingInterfaceFilter", "cali@123", "", false),

	Entry("HealthTimeoutOverrides", "HealthTimeoutOverrides", "", map[string]time.Duration(nil), false),
	Entry("HealthTimeoutOverrides good", "HealthTimeoutOverrides", "a=90s", map[string]time.Duration{"a": 90 * time.Second}, false),
	Entry("HealthTimeoutOverrides good x 2", "HealthTimeoutOverrides", "a=90s, b=10ms",
		map[string]time.Duration{"a": 90 * time.Second, "b": 10 * time.Millisecond}, false),
	Entry("HealthTimeoutOverrides good zero", "HealthTimeoutOverrides", "a=0",
		map[string]time.Duration{"a": 0}, false),
	// Not a required parameter so a bad value is translated to nil:
	Entry("HealthTimeoutOverrides non-duration", "HealthTimeoutOverrides", "foo=bar", map[string]time.Duration(nil), false),

	Entry("BPFForceTrackPacketsFromIfaces Empty", "BPFForceTrackPacketsFromIfaces", "", []string{"docker+"}),
	Entry("BPFForceTrackPacketsFromIfaces Single valid entry", "BPFForceTrackPacketsFromIfaces", "docker0", []string{"docker0"}),
	Entry("BPFForceTrackPacketsFromIfaces Single valid entry", "BPFForceTrackPacketsFromIfaces", "cali-123", []string{"cali-123"}),
	Entry("BPFForceTrackPacketsFromIfaces Single valid wildcard", "BPFForceTrackPacketsFromIfaces", "docker+", []string{"docker+"}),
	Entry("BPFForceTrackPacketsFromIfaces Multiple valid entries", "BPFForceTrackPacketsFromIfaces", "docker0,docker1", []string{"docker0", "docker1"}),
	Entry("BPFForceTrackPacketsFromIfaces Single invalid entry", "BPFForceTrackPacketsFromIfaces", "cali@123", []string{"docker+"}),
	Entry("BPFForceTrackPacketsFromIfaces Multiple invalid entries", "BPFForceTrackPacketsFromIfaces", "cali-123,cali@123", []string{"docker+"}),

	Entry("RequireMTUFile valid", "RequireMTUFile", "true", true),
	Entry("RequireMTUFile valid", "RequireMTUFile", "y", true),
	Entry("RequireMTUFile valid", "RequireMTUFile", "True", true),
)

var _ = DescribeTable("OpenStack heuristic tests",
	func(clusterType, metadataAddr, metadataPort, ifacePrefixes interface{}, expected bool) {
		c := config.New()
		values := make(map[string]string)
		if clusterType != nil {
			values["ClusterType"] = clusterType.(string)
		}
		if metadataAddr != nil {
			values["MetadataAddr"] = metadataAddr.(string)
		}
		if metadataPort != nil {
			values["MetadataPort"] = metadataPort.(string)
		}
		if ifacePrefixes != nil {
			values["InterfacePrefix"] = ifacePrefixes.(string)
		}
		_, err := c.UpdateFrom(values, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.OpenstackActive()).To(Equal(expected))
	},
	Entry("no config", nil, nil, nil, nil, false),

	Entry("explicit openstack as cluster type", "openstack", nil, nil, nil, true),
	Entry("explicit openstack at start of cluster type", "openstack,k8s", nil, nil, nil, true),
	Entry("explicit openstack at end of cluster type", "k8s,openstack", nil, nil, nil, true),
	Entry("explicit openstack in middle of cluster type", "k8s,openstack,k8s", nil, nil, nil, true),

	Entry("metadataAddr set", nil, "10.0.0.1", nil, nil, true),
	Entry("metadataAddr = none", nil, "none", nil, nil, false),
	Entry("metadataAddr = ''", nil, "", nil, nil, false),

	Entry("metadataPort set", nil, nil, "1234", nil, true),
	Entry("metadataPort = none", nil, nil, "none", nil, false),

	Entry("ifacePrefixes = tap", nil, nil, nil, "tap", true),
	Entry("ifacePrefixes = cali,tap", nil, nil, nil, "cali,tap", true),
	Entry("ifacePrefixes = tap,cali ", nil, nil, nil, "tap,cali", true),
	Entry("ifacePrefixes = cali ", nil, nil, nil, "cali", false),
)

var _ = DescribeTable("Kubernetes Provider tests",
	func(clusterType string, expected config.Provider) {
		c := config.New()
		c.ClusterType = clusterType
		Expect(c.KubernetesProvider()).To(Equal(expected))
	},
	Entry("no config", nil, config.ProviderNone),

	Entry("explicit provider as cluster type", "aks", config.ProviderAKS),
	Entry("explicit provider at start of cluster type", "AKS,k8s", config.ProviderAKS),
	Entry("explicit provider at end of cluster type", "k8s,aks", config.ProviderAKS),
	Entry("explicit provider in middle of cluster type", "k8s,EKS,k8s", config.ProviderEKS),
	Entry("no explicit provider in cluster type", "k8s,something,else", config.ProviderNone),

	Entry("EKS provider", "k8s,eks", config.ProviderEKS),
	Entry("GKE provider", "GKE,k8s", config.ProviderGKE),
	Entry("AKS provider", "Aks,k8s", config.ProviderAKS),
	Entry("OpenShift provider", "OpenShift,k8s", config.ProviderOpenShift),
	Entry("DockerEE provider", "dockerenterprise,k8s", config.ProviderDockerEE),
)

var _ = Describe("DatastoreConfig tests", func() {
	var c *config.Config
	Describe("with IPIP enabled", func() {
		BeforeEach(func() {
			c = config.New()
			c.DatastoreType = "k8s"
			t := true
			c.IpInIpEnabled = &t
			c.Encapsulation.IPIPEnabled = true
		})
		It("should leave node polling enabled", func() {
			Expect(c.DatastoreConfig().Spec.K8sDisableNodePoll).To(BeFalse())
		})
	})
	Describe("with IPIP disabled", func() {
		BeforeEach(func() {
			c = config.New()
			c.DatastoreType = "k8s"
			f := false
			c.IpInIpEnabled = &f
			c.Encapsulation.IPIPEnabled = false
		})
		It("should leave node polling enabled", func() {
			Expect(c.DatastoreConfig().Spec.K8sDisableNodePoll).To(BeTrue())
		})
	})

	Describe("with the configuration set only from the common calico configuration", func() {
		BeforeEach(func() {
			c = config.New()
			c.SetLoadClientConfigFromEnvironmentFunction(func() (*apiconfig.CalicoAPIConfig, error) {
				return &apiconfig.CalicoAPIConfig{
					Spec: apiconfig.CalicoAPIConfigSpec{
						DatastoreType: apiconfig.EtcdV3,
						EtcdConfig: apiconfig.EtcdConfig{
							EtcdEndpoints:  "http://localhost:1234",
							EtcdKeyFile:    testutils.TestDataFile("etcdkeyfile.key"),
							EtcdCertFile:   testutils.TestDataFile("etcdcertfile.cert"),
							EtcdCACertFile: testutils.TestDataFile("etcdcacertfile.cert"),
						},
					},
				}, nil
			})
		})
		It("sets the configuration options", func() {
			spec := c.DatastoreConfig().Spec
			Expect(spec.DatastoreType).To(Equal(apiconfig.EtcdV3))
			Expect(spec.EtcdEndpoints).To(Equal("http://localhost:1234"))
			Expect(spec.EtcdKeyFile).To(Equal(testutils.TestDataFile("etcdkeyfile.key")))
			Expect(spec.EtcdCertFile).To(Equal(testutils.TestDataFile("etcdcertfile.cert")))
			Expect(spec.EtcdCACertFile).To(Equal(testutils.TestDataFile("etcdcacertfile.cert")))
		})
	})
	Describe("without setting the DatastoreType and setting the etcdv3 suboptions through the felix configuration", func() {
		BeforeEach(func() {
			c = config.New()
			_, err := c.UpdateFrom(map[string]string{
				"EtcdEndpoints": "http://localhost:1234",
				"EtcdKeyFile":   testutils.TestDataFile("etcdkeyfile.key"),
				"EtcdCertFile":  testutils.TestDataFile("etcdcertfile.cert"),
				"EtcdCaFile":    testutils.TestDataFile("etcdcacertfile.cert"),
			}, config.EnvironmentVariable)
			Expect(err).NotTo(HaveOccurred())
		})
		It("sets the etcd suboptions", func() {
			spec := c.DatastoreConfig().Spec
			Expect(spec.DatastoreType).To(Equal(apiconfig.EtcdV3))
			Expect(spec.EtcdEndpoints).To(Equal("http://localhost:1234/"))
			Expect(spec.EtcdKeyFile).To(Equal(testutils.TestDataFile("etcdkeyfile.key")))
			Expect(spec.EtcdCertFile).To(Equal(testutils.TestDataFile("etcdcertfile.cert")))
			Expect(spec.EtcdCACertFile).To(Equal(testutils.TestDataFile("etcdcacertfile.cert")))
		})
	})
	Describe("with the configuration set from the common calico configuration and the felix configuration", func() {
		BeforeEach(func() {
			c = config.New()

			c.SetLoadClientConfigFromEnvironmentFunction(func() (*apiconfig.CalicoAPIConfig, error) {
				return &apiconfig.CalicoAPIConfig{
					Spec: apiconfig.CalicoAPIConfigSpec{
						DatastoreType: apiconfig.Kubernetes,
						EtcdConfig: apiconfig.EtcdConfig{
							EtcdEndpoints:  "http://localhost:5432",
							EtcdKeyFile:    testutils.TestDataFile("etcdkeyfileother.key"),
							EtcdCertFile:   testutils.TestDataFile("etcdcertfileother.cert"),
							EtcdCACertFile: testutils.TestDataFile("etcdcacertfileother.cert"),
						},
					},
				}, nil
			})

			_, err := c.UpdateFrom(map[string]string{
				"DatastoreType": "etcdv3",
				"EtcdEndpoints": "http://localhost:1234",
				"EtcdKeyFile":   testutils.TestDataFile("etcdkeyfile.key"),
				"EtcdCertFile":  testutils.TestDataFile("etcdcertfile.cert"),
				"EtcdCaFile":    testutils.TestDataFile("etcdcacertfile.cert"),
			}, config.EnvironmentVariable)
			Expect(err).NotTo(HaveOccurred())
		})
		It("sets the configuration to what the felix configuration is", func() {
			spec := c.DatastoreConfig().Spec
			Expect(spec.DatastoreType).To(Equal(apiconfig.EtcdV3))
			Expect(spec.EtcdEndpoints).To(Equal("http://localhost:1234/"))
			Expect(spec.EtcdKeyFile).To(Equal(testutils.TestDataFile("etcdkeyfile.key")))
			Expect(spec.EtcdCertFile).To(Equal(testutils.TestDataFile("etcdcertfile.cert")))
			Expect(spec.EtcdCACertFile).To(Equal(testutils.TestDataFile("etcdcacertfile.cert")))
		})
	})
})

var _ = DescribeTable("Config validation",
	func(settings map[string]string, ok bool) {
		cfg := config.New()
		_, err := cfg.UpdateFrom(settings, config.ConfigFile)
		log.WithError(err).Info("UpdateFrom result")
		if err == nil {
			err = cfg.Validate()
			log.WithError(err).Info("Validation result")
		}
		if !ok {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).NotTo(HaveOccurred())
		}
	},

	Entry("no settings", map[string]string{}, true),
	Entry("just one TLS setting", map[string]string{
		"TyphaKeyFile": "/usr",
	}, false),
	Entry("TLS certs and key but no CN or URI SAN", map[string]string{
		"TyphaKeyFile":  "/usr",
		"TyphaCertFile": "/usr",
		"TyphaCAFile":   "/usr",
	}, false),
	Entry("TLS certs and key and CN but no URI SAN", map[string]string{
		"TyphaKeyFile":  "/usr",
		"TyphaCertFile": "/usr",
		"TyphaCAFile":   "/usr",
		"TyphaCN":       "typha-peer",
	}, true),
	Entry("TLS certs and key and URI SAN but no CN", map[string]string{
		"TyphaKeyFile":  "/usr",
		"TyphaCertFile": "/usr",
		"TyphaCAFile":   "/usr",
		"TyphaURISAN":   "spiffe://k8s.example.com/typha-peer",
	}, true),
	Entry("all Felix-Typha TLS params", map[string]string{
		"TyphaKeyFile":  "/usr",
		"TyphaCertFile": "/usr",
		"TyphaCAFile":   "/usr",
		"TyphaCN":       "typha-peer",
		"TyphaURISAN":   "spiffe://k8s.example.com/typha-peer",
	}, true),
	Entry("valid OpenstackRegion", map[string]string{
		"OpenstackRegion": "region1",
	}, true),
	Entry("OpenstackRegion with uppercase", map[string]string{
		"OpenstackRegion": "RegionOne",
	}, false),
	Entry("OpenstackRegion with slash", map[string]string{
		"OpenstackRegion": "us/east",
	}, false),
	Entry("OpenstackRegion with underscore", map[string]string{
		"OpenstackRegion": "my_region",
	}, false),
	Entry("OpenstackRegion too long", map[string]string{
		"OpenstackRegion": "my-region-has-a-very-long-and-extremely-interesting-name",
	}, false),
	Entry("valid RouteTableRange", map[string]string{
		"RouteTableRange": "1-250",
	}, true),
	Entry("invalid RouteTableRange", map[string]string{
		"RouteTableRange": "1-255",
	}, false),
	Entry("valid RouteTableRanges", map[string]string{
		"RouteTableRanges": "1-10000",
	}, true),
	// 0xFFFFFFFF + 1
	Entry("overflowing RouteTableRanges", map[string]string{
		"RouteTableRanges": "4294967295-4294967296",
	}, false),
	// exceeds max allowed number of individual tables
	Entry("excessive RouteTableRanges", map[string]string{
		"RouteTableRanges": "1-100000000",
	}, false),
	Entry("excessive RouteTableRanges off-by-one", map[string]string{
		"RouteTableRanges": "1-65535,99999-99999",
	}, false),
	Entry("RouteTableRanges 32-bit wrap-around", map[string]string{
		"RouteTableRanges": "1-65535,1-2147483647",
	}, false),
	Entry("invalid RouteTableRanges", map[string]string{
		"RouteTableRanges": "abcde",
	}, false),
)

var _ = DescribeTable("Config InterfaceExclude",
	func(excludeList string, expected []*regexp.Regexp) {
		cfg := config.New()
		_, err := cfg.UpdateFrom(map[string]string{"InterfaceExclude": excludeList}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())
		regexps := cfg.InterfaceExclude
		Expect(regexps).To(Equal(expected))
	},

	Entry("empty exclude list", "", []*regexp.Regexp{
		regexp.MustCompile("^kube-ipvs0$"),
	}),
	Entry("non-regexp single value", "kube-ipvs0", []*regexp.Regexp{
		regexp.MustCompile("^kube-ipvs0$"),
	}),
	Entry("non-regexp multiple values", "kube-ipvs0,veth1", []*regexp.Regexp{
		regexp.MustCompile("^kube-ipvs0$"),
		regexp.MustCompile("^veth1$"),
	}),
	Entry("regexp single value", "/^veth.*/", []*regexp.Regexp{
		regexp.MustCompile("^veth.*"),
	}),
	Entry("regexp multiple values", "/veth/,/^kube.*/", []*regexp.Regexp{
		regexp.MustCompile("veth"),
		regexp.MustCompile("^kube.*"),
	}),
	Entry("both non-regexp and regexp values", "kube-ipvs0,/veth/,/^kube.*/", []*regexp.Regexp{
		regexp.MustCompile("^kube-ipvs0$"),
		regexp.MustCompile("veth"),
		regexp.MustCompile("^kube.*"),
	}),
	Entry("invalid non-regexp value", `not.a.valid.interf@e!!`, []*regexp.Regexp{
		regexp.MustCompile("^kube-ipvs0$"),
	}),
	Entry("invalid regexp value", `/^kube\K/`, []*regexp.Regexp{
		regexp.MustCompile("^kube-ipvs0$"),
	}),
)

var _ = Describe("Config copy tests", func() {
	var conf *config.Config

	BeforeEach(func() {
		conf = config.New()
		changed, err := conf.UpdateFrom(map[string]string{
			"LogSeverityScreen":            "Debug",
			"HealthTimeoutOverrides":       "a=10s, b=0,c=50ms",
			"DisableConntrackInvalidCheck": "true",
		}, config.DatastoreGlobal)
		Expect(err).To(Succeed())
		Expect(changed).To(BeTrue())
		changed, err = conf.UpdateFrom(map[string]string{
			"LogSeverityScreen":      "Info",
			"HealthTimeoutOverrides": "a=6s",
		}, config.EnvironmentVariable)
		Expect(err).To(Succeed())
		Expect(changed).To(BeTrue())
	})

	It("should copy correctly", func() {
		Expect(conf.RawValues()).To(Equal(conf.Copy().RawValues()))
	})

	It("should copy via protobuf correctly UpdateFromConfigUpdate", func() {
		pb := conf.ToConfigUpdate()
		confCp := config.New()
		changedFields, err := confCp.UpdateFromConfigUpdate(pb)
		Expect(err).To(Succeed())
		Expect(changedFields).To(Equal(set.From(
			"HealthTimeoutOverrides",
			"DisableConntrackInvalidCheck",
		)))
		Expect(confCp.RawValues()).To(Equal(conf.RawValues()))

		changedFields, err = confCp.UpdateFromConfigUpdate(pb)
		Expect(err).To(Succeed())
		Expect(changedFields).To(BeEmpty())
		Expect(confCp.RawValues()).To(Equal(conf.RawValues()))
	})

	It("should copy via protobuf correctly FromConfigUpdate", func() {
		pb := conf.ToConfigUpdate()
		confCp := config.FromConfigUpdate(pb)
		Expect(confCp.RawValues()).To(Equal(conf.RawValues()))

		changedFields, err := confCp.UpdateFromConfigUpdate(pb)
		Expect(err).To(Succeed())
		Expect(changedFields).To(BeEmpty())
		Expect(confCp.RawValues()).To(Equal(conf.RawValues()))
	})
})

var _ = DescribeTable("SafeParamsEqual",
	func(a, b any, expected bool) {
		Expect(config.SafeParamsEqual(a, b)).To(Equal(expected), fmt.Sprintf("SafeParamsEqual(%v, %v) != expected (%v)", a, b, expected))
		Expect(config.SafeParamsEqual(b, a)).To(Equal(expected), fmt.Sprintf("SafeParamsEqual(%v, %v) != expected (%v)", b, a, expected))
	},
	Entry("empty", "", "", true),
	Entry("different strings", "foo", "", false),
	Entry("same regexps", regexp.MustCompile("[123]"), regexp.MustCompile("[123]"), true),
	Entry("different regexps", regexp.MustCompile("[123]"), regexp.MustCompile("[1234]"), false),
	Entry("same []regexps",
		[]*regexp.Regexp{regexp.MustCompile("[123]"), regexp.MustCompile("[1234]")},
		[]*regexp.Regexp{regexp.MustCompile("[123]"), regexp.MustCompile("[1234]")},
		true,
	),
	Entry("different []regexps",
		[]*regexp.Regexp{regexp.MustCompile("[123]"), regexp.MustCompile("[1234]")},
		[]*regexp.Regexp{regexp.MustCompile("[123]"), regexp.MustCompile("[124]")},
		false,
	),
	Entry("different length []regexps",
		[]*regexp.Regexp{regexp.MustCompile("[123]"), regexp.MustCompile("[1234]")},
		[]*regexp.Regexp{regexp.MustCompile("[123]")},
		false,
	),
	Entry("nil IPs",
		net.IP(nil),
		net.IP(nil),
		true,
	),
	Entry("same IPs",
		net.ParseIP("10.0.0.1"),
		net.ParseIP("10.0.0.1"),
		true,
	),
	Entry("equivalent IPs",
		net.ParseIP("10.0.0.1").To4(),
		net.ParseIP("10.0.0.1").To16(),
		true,
	),
	Entry("different IPs",
		net.ParseIP("10.0.0.2"),
		net.ParseIP("10.0.0.1"),
		false,
	),
)
