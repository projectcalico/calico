// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package emitter

import "sigs.k8s.io/controller-runtime/pkg/client"

type Option func(*Emitter)

func WithURL(url string) Option {
	return func(e *Emitter) {
		e.url = url
	}
}

func WithCACertPath(path string) Option {
	return func(e *Emitter) {
		e.caCert = path
	}
}

func WithClientKeyPath(path string) Option {
	return func(e *Emitter) {
		e.clientKey = path
	}
}

func WithClientCertPath(path string) Option {
	return func(e *Emitter) {
		e.clientCert = path
	}
}

func WithKubeClient(kcli client.Client) Option {
	return func(e *Emitter) {
		e.kcli = kcli
	}
}

func WithServerName(name string) Option {
	return func(e *Emitter) {
		e.serverName = name
	}
}
