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

package config_test

import (
	. "github.com/projectcalico/felix/go/felix/config"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"path"
	"runtime"
)

const confFileSingleParamNoNewLine = `[ignored]
FelixHostname=hostname`

const confFileDefaultBlock = `[default]
FelixHostname=hostname`

const confFileMultiBlock = `[ignored]
FelixHostname=hostname
[logging]
LogSeverityScreen=INFO
LogSeveritySys=DEBUG`

var _ = DescribeTable("File parameter parsing",
	func(fileContent string, expected map[string]string) {
		actual, err := LoadConfigFileData([]byte(fileContent))
		Expect(err).To(BeNil())
		Expect(actual).To(Equal(expected))
	},
	Entry("Empty", "", map[string]string{}),
	Entry("Single param", confFileSingleParamNoNewLine, map[string]string{
		"FelixHostname": "hostname",
	}),
	Entry("Default block", confFileDefaultBlock, map[string]string{
		"FelixHostname": "hostname",
	}),
	Entry("Multi block", confFileMultiBlock, map[string]string{
		"FelixHostname":     "hostname",
		"LogSeverityScreen": "INFO",
		"LogSeveritySys":    "DEBUG",
	}),
)

var _ = DescribeTable("File load tests",
	func(filename string, expected map[string]string, errExpected bool) {
		myDir := myDir()
		path := path.Join(myDir, "testdata", filename)
		value, err := LoadConfigFile(path)
		if errExpected {
			Expect(err).ToNot(BeNil())
		} else {
			Expect(err).To(BeNil())
		}
		Expect(value).To(Equal(expected))
	},
	Entry("Missing", "missing.cfg", nil, false),
	Entry("Empty", "empty.cfg", map[string]string{}, false),
	Entry("Mainline", "mainline.cfg", map[string]string{
		"FelixHostname":     "hostname",
		"LogSeverityScreen": "INFO",
		"LogSeveritySys":    "DEBUG",
	}, false),
	Entry("Malformed", "malformed.cfg", nil, true),
)

func myDir() string {
	_, filename, _, ok := runtime.Caller(1)
	if !ok {
		panic("Failed to get my directory to load test data")
	}
	return path.Dir(filename)
}
