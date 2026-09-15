// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package securitycontext

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

var (
	// It is recommended to choose UID and GID that don't collide with existing system users and groups.
	// Non-system UID and GID range is normally from 1000 to 60000 (Debian derived systems define this
	// in /etc/login.defs). On a normal Linux host, it is unlikely to have more than 10k non-system users.
	// 10001 is chosen based on this assumption.
	runAsUserID  int64 = 10001
	runAsGroupID int64 = 10001
)

// NewNonRootContext returns the non-root and non-privileged container security context that most of
// the containers should be using.
func NewNonRootContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
		Privileged:   ptr.To(false),
		RunAsGroup:   ptr.To(runAsGroupID),
		RunAsNonRoot: ptr.To(true),
		RunAsUser:    &runAsUserID,
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
}

// NewRootContext returns the root container security context for containers that access host files or network.
func NewRootContext(privileged bool) *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(privileged),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
		Privileged:   ptr.To(privileged),
		RunAsGroup:   ptr.To(int64(0)),
		RunAsNonRoot: ptr.To(false),
		RunAsUser:    ptr.To(int64(0)),
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
}

func NewWindowsHostProcessContext() *corev1.SecurityContext {
	t := true
	user := "NT AUTHORITY\\system"
	return &corev1.SecurityContext{
		WindowsOptions: &corev1.WindowsSecurityContextOptions{
			HostProcess:   &t,
			RunAsUserName: &user,
		},
	}
}

// NewNonRootPodContext returns the non-root and non-privileged pod security context for pods that container
// security context can't be set directly.
func NewNonRootPodContext() *corev1.PodSecurityContext {
	return &corev1.PodSecurityContext{
		RunAsGroup:   ptr.To(runAsGroupID),
		RunAsNonRoot: ptr.To(true),
		RunAsUser:    ptr.To(runAsUserID),
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
}
