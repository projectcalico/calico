// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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

package elastic

import (
	"context"
	"fmt"

	"github.com/stretchr/testify/mock"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type MockESClientKey string

type MockESClient struct {
	mock.Mock
}

func MockESCLICreator(_ client.Client, ctx context.Context, _ string, _ bool) (utils.ElasticClient, error) {
	if esCli := ctx.Value(MockESClientKey("mockESClient")); esCli != nil {
		return esCli.(*MockESClient), nil
	}
	return &MockESClient{}, nil
}

func (m *MockESClient) CreateUser(_ context.Context, _ *utils.User) error {
	return fmt.Errorf("CreateUser not implemented in mock client")
}

func (m *MockESClient) SetILMPolicies(_ context.Context, _ *operatorv1.LogStorage, _ bool) error {
	return nil
}

func (m *MockESClient) DeleteRoles(ctx context.Context, roles []utils.Role) error {
	var ret mock.Arguments
	for _, role := range roles {
		ret = m.MethodCalled("deleteRole", ctx, role)
		if ret.Error(0) != nil {
			return ret.Error(0)
		}
	}

	ret = m.Called(ctx, roles)
	return ret.Error(0)
}

func (m *MockESClient) DeleteUser(ctx context.Context, u *utils.User) error {
	ret := m.MethodCalled("DeleteRoles", ctx, u.Roles)
	if ret.Error(0) != nil {
		return ret.Error(0)
	}

	ret = m.Called(ctx, u)
	return ret.Error(0)
}

func (m *MockESClient) GetUsers(ctx context.Context) ([]utils.User, error) {
	ret := m.Called(ctx)
	return ret.Get(0).([]utils.User), ret.Error(1)
}
