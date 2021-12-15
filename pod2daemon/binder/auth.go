// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package binder

import (
	"golang.org/x/net/context"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const (
	authType = "udsuspver"
)

// TODO relocate to shared location
type Credentials struct {
	Uid            string
	Workload       string
	Namespace      string
	ServiceAccount string
}

func (c Credentials) AuthType() string {
	return authType
}

func CallerFromContext(ctx context.Context) (Credentials, bool) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return Credentials{}, false
	}
	return CallerFromAuthInfo(peer.AuthInfo)
}

func CallerFromAuthInfo(ainfo credentials.AuthInfo) (Credentials, bool) {
	if ci, ok := ainfo.(Credentials); ok {
		return ci, true
	}
	return Credentials{}, false
}
