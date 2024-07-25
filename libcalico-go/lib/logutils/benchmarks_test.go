// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.
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

package logutils

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func BenchmarkLogWithOurFormat(b *testing.B) {
	logger := logrus.New()
	logger.SetFormatter(&Formatter{})
	logger.SetReportCaller(true)
	logger.SetOutput(&NullWriter{})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		logger.Info("Test log")
	}
}

func BenchmarkLogWithOurFormatFixedFields(b *testing.B) {
	logger := logrus.New()
	logger.SetFormatter(&Formatter{})
	logger.SetReportCaller(true)
	logger.SetOutput(&NullWriter{})

	b.ResetTimer()
	b.ReportAllocs()

	entry := logger.WithFields(logrus.Fields{
		"a": "b",
		"c": "d",
		"e": "f",
		"g": "h",
	})

	for i := 0; i < b.N; i++ {
		entry.Info("Test log")
	}
}

func BenchmarkLogWithFieldOurFormat(b *testing.B) {
	logger := logrus.New()
	logger.SetFormatter(&Formatter{})
	logger.SetReportCaller(true)
	logger.SetOutput(&NullWriter{})

	b.ResetTimer()
	b.ReportAllocs()

	entry := logger.WithFields(logrus.Fields{
		"a": "b",
		"c": "d",
		"e": "f",
		"g": "h",
	})

	for i := 0; i < b.N; i++ {
		entry.WithField("f", "g").Info("Test log")
	}
}

func BenchmarkLogWithFieldsOurFormat(b *testing.B) {
	logger := logrus.New()
	logger.SetFormatter(&Formatter{})
	logger.SetReportCaller(true)
	logger.SetOutput(&NullWriter{})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		logger.WithFields(logrus.Fields{
			"a": "b",
			"c": "d",
			"e": "f",
			"g": "h",
		}).Info("Test log")
	}
}
