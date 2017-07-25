// +build fvtests

// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package k8s_test

import (
	"os"
	"testing"

	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/logutils"
)

func init() {
	//testutils.HookLogrusForGinkgo()
	logutils.ConfigureEarlyLogging()
	logLevel, err := log.ParseLevel(os.Getenv("K8SFV_LOG_LEVEL"))
	if err == nil {
		log.SetLevel(logLevel)
	}
	log.SetLevel(log.InfoLevel)
	//flag.StringVar(&k8sServerIP, "k8s-apiserver-ip", "", "")
	//flag.StringVar(&k8sServerEndpoint, "k8s-api-endpoint", "", "")
	//flag.StringVar(&felixIP, "felix-ip", "", "")
	//flag.StringVar(&felixHostname, "felix-hostname", "", "")
	//flag.StringVar(&prometheusPushURL, "prometheus-push-url", "", "")
	//flag.StringVar(&codeLevel, "code-level", "", "")
	//flag.StringVar(&typhaIP, "typha-ip", "", "")
}

func TestWithKubernetesServer(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("junit.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Felix/KDD FV tests",
		[]Reporter{junitReporter})
}
