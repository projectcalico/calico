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
	. "github.com/projectcalico/typha/pkg/config"

	"reflect"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Config parsing",
	func(key, value string, expected interface{}, errorExpected ...bool) {
		config := New()
		_, err := config.UpdateFrom(map[string]string{key: value},
			EnvironmentVariable)
		newVal := reflect.ValueOf(config).Elem().FieldByName(key).Interface()
		Expect(newVal).To(Equal(expected))
		if len(errorExpected) > 0 && errorExpected[0] {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).NotTo(HaveOccurred())
		}
	},

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

	Entry("LogFilePath", "LogFilePath", "/tmp/typha.log", "/tmp/typha.log"),

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

	Entry("HealthEnabled", "HealthEnabled", "true", true),
	Entry("HealthHost", "HealthHost", "127.0.0.1", "127.0.0.1"),
	Entry("HealthPort", "HealthPort", "1234", int(1234)),

	Entry("PrometheusMetricsEnabled", "PrometheusMetricsEnabled", "true", true),
	Entry("PrometheusMetricsPort", "PrometheusMetricsPort", "1234", int(1234)),
	Entry("PrometheusGoMetricsEnabled", "PrometheusGoMetricsEnabled", "false", false),
	Entry("PrometheusProcessMetricsEnabled", "PrometheusProcessMetricsEnabled", "false", false),
)
