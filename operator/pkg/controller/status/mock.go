// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package status

import (
	"context"

	"github.com/go-logr/logr"

	operator "github.com/tigera/operator/api/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/mock"
	"k8s.io/apimachinery/pkg/types"
)

// TODO use mockery to generate mock
type MockStatus struct {
	mock.Mock
}

func (m *MockStatus) Run(context.Context) {
	m.Called()
}

func (m *MockStatus) ReadyToMonitor() {
	m.Called()
}

func (m *MockStatus) OnCRFound() {
	m.Called()
}

func (m *MockStatus) OnCRNotFound() {
	m.Called()
}

func (m *MockStatus) AddDaemonsets(dss []types.NamespacedName) {
	m.Called(dss)
}

func (m *MockStatus) AddDeployments(deps []types.NamespacedName) {
	m.Called(deps)
}

func (m *MockStatus) AddStatefulSets(sss []types.NamespacedName) {
	m.Called(sss)
}

func (m *MockStatus) AddCronJobs(cjs []types.NamespacedName) {
	m.Called(cjs)
}

func (m *MockStatus) AddCertificateSigningRequests(name string, labels map[string]string) {
	m.Called(name)
}

func (m *MockStatus) RemoveDaemonsets(dss ...types.NamespacedName) {
	m.Called(dss)
}

func (m *MockStatus) RemoveDeployments(dps ...types.NamespacedName) {
	m.Called(dps)
}

func (m *MockStatus) RemoveStatefulSets(sss ...types.NamespacedName) {
	m.Called(sss)
}

func (m *MockStatus) RemoveCronJobs(cjs ...types.NamespacedName) {
	m.Called(cjs)
}

func (m *MockStatus) RemoveCertificateSigningRequests(label string) {
	m.Called(label)
}

func (m *MockStatus) SetDegraded(reason operator.TigeraStatusReason, msg string, err error, log logr.Logger) {
	if err != nil {
		m.Called(reason, msg, err.Error(), log)
	} else {
		m.Called(reason, msg, err, log)
	}
}

func (m *MockStatus) ClearDegraded() {
	m.Called()
}

func (m *MockStatus) SetWarning(key string, msg string) {
	m.Called(key, msg)
}

func (m *MockStatus) ClearWarning(key string) {
	m.Called(key)
}

func (m *MockStatus) IsAvailable() bool {
	return m.Called().Bool(0)
}

func (m *MockStatus) IsProgressing() bool {
	return m.Called().Bool(0)
}

func (m *MockStatus) IsDegraded() bool {
	return m.Called().Bool(0)
}

func (m *MockStatus) WasCalled(method string, arguments ...interface{}) bool {
	for _, call := range m.Calls {
		if call.Method == method {
			_, diffCount := call.Arguments.Diff(arguments)
			if diffCount == 0 {
				return true
			}
		}
	}
	return false
}

func (m *MockStatus) SetMetaData(meta *metav1.ObjectMeta) {
	m.Called(meta)
}
