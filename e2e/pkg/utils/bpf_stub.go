// Copyright (c) 2026 Tigera, Inc. All rights reserved.

//go:build !cgo

package utils

import (
	"fmt"

	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func DumpBPFNATServiceBackends(cs kubernetes.Interface, nodeName string, serviceIP string, servicePort int, proto corev1.Protocol) (set.Set[string], error) {
	gomega.Fail("DumpBPFNATServiceBackends requires CGO (libbpf) but it is not enabled")
	return nil, fmt.Errorf("DumpBPFNATServiceBackends requires CGO (libbpf) but it is not enabled")
}
