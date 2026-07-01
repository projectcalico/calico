// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package main

import (
	"testing"
)

// findJob returns the first ResolvedJob whose env matches all of want, or nil.
func findJob(jobs []ResolvedJob, want map[string]string) *ResolvedJob {
	for i := range jobs {
		match := true
		for k, v := range want {
			if jobs[i].Env[k] != v {
				match = false
				break
			}
		}
		if match {
			return &jobs[i]
		}
	}
	return nil
}

func TestExpandNftables(t *testing.T) {
	p, err := LoadPipeline("testdata/nftables.yml")
	if err != nil {
		t.Fatalf("LoadPipeline: %v", err)
	}
	jobs := Expand(p)

	// nftables.yml expands to 10 concrete runs:
	//   arm64/WG block:  1 job × (K8S_VERSION[1] × CLUSTER_IMAGE[2]) = 2
	//   Talos block:     3 jobs (Talos[matrix 1], native-CRD GCP, native-CRD AWS) = 3
	//   EKS block:       2 jobs (aws-CNI[matrix 1], calico-CNI[matrix 1]) = 2
	//   KinD block:      2 jobs (dual-stack, ipv6-only) = 2
	//   KubeVirt block:  1 job = 1
	if got, want := len(jobs), 10; got != want {
		t.Errorf("resolved job count = %d, want %d", got, want)
		for _, j := range jobs {
			t.Logf("  [%s] %s", j.Block, j.Job)
		}
	}

	t.Run("global env is the base layer", func(t *testing.T) {
		// DATAPLANE/KUBE_PROXY_MODE come only from global_job_config; every
		// job must carry them.
		for _, j := range jobs {
			if j.Env["DATAPLANE"] != "CalicoNftables" {
				t.Errorf("[%s] %s: DATAPLANE=%q, want CalicoNftables", j.Block, j.Job, j.Env["DATAPLANE"])
			}
			if j.Env["KUBE_PROXY_MODE"] != "nftables" {
				t.Errorf("[%s] %s: KUBE_PROXY_MODE=%q, want nftables", j.Block, j.Job, j.Env["KUBE_PROXY_MODE"])
			}
		}
	})

	t.Run("matrix expands and overrides global", func(t *testing.T) {
		// The arm64 rocky variant: matrix K8S_VERSION=stable overrides the
		// global default (stable-3); job env sets PROVISIONER + WireGuard.
		j := findJob(jobs, map[string]string{"CLUSTER_IMAGE": "rocky-linux-9-arm64"})
		if j == nil {
			t.Fatal("no job with CLUSTER_IMAGE=rocky-linux-9-arm64")
		}
		checks := map[string]string{
			"K8S_VERSION":      "stable",       // matrix overrides global stable-3
			"PROVISIONER":      "gcp-kubeadm",  // job env
			"ENABLE_WIREGUARD": "true",         // job env
			"STERN_CHECK":      "DISABLED",     // job env
		}
		for k, want := range checks {
			if j.Env[k] != want {
				t.Errorf("arm64/rocky: %s=%q, want %q", k, j.Env[k], want)
			}
		}
		// The ubuntu variant must also exist and differ only in CLUSTER_IMAGE.
		if findJob(jobs, map[string]string{"CLUSTER_IMAGE": "ubuntu-2204-lts-arm64"}) == nil {
			t.Error("no job with CLUSTER_IMAGE=ubuntu-2204-lts-arm64")
		}
	})

	t.Run("job env overrides global (native-CRD, EKS selection)", func(t *testing.T) {
		// The EKS Calico-CNI job overrides K8S_E2E_FLAGS at the job layer with
		// a longer skip list than the global value.
		j := findJob(jobs, map[string]string{"PROVISIONER": "aws-eks", "CNI_PLUGIN": "Calico"})
		if j == nil {
			t.Fatal("no EKS Calico-CNI job")
		}
		if j.Env["INSTALLER"] != "helmerator" {
			t.Errorf("EKS calico: INSTALLER=%q, want helmerator (job override of global operator)", j.Env["INSTALLER"])
		}
		if j.Env["IPV4_POD_CIDR"] != "172.16.0.0/16" {
			t.Errorf("EKS calico: IPV4_POD_CIDR=%q, want 172.16.0.0/16", j.Env["IPV4_POD_CIDR"])
		}
	})

	t.Run("KubeVirt job uses E2E_TEST_CONFIG (Mode 1)", func(t *testing.T) {
		j := findJob(jobs, map[string]string{"E2E_TEST_CONFIG": "e2e/config/gcp-kubevirt.yaml"})
		if j == nil {
			t.Fatal("no job with E2E_TEST_CONFIG=e2e/config/gcp-kubevirt.yaml")
		}
		// Block-level env (NUM_KUBEVIRT_VMS, PROVISIONER) must merge in.
		if j.Env["NUM_KUBEVIRT_VMS"] != "2" {
			t.Errorf("KubeVirt: NUM_KUBEVIRT_VMS=%q, want 2 (block env)", j.Env["NUM_KUBEVIRT_VMS"])
		}
		if j.Env["PROVISIONER"] != "gcp-kubeadm" {
			t.Errorf("KubeVirt: PROVISIONER=%q, want gcp-kubeadm (block env)", j.Env["PROVISIONER"])
		}
	})

	t.Run("KinD block-level task env merges into every job", func(t *testing.T) {
		// The KinD block sets PROVISIONER=local-kind + ENABLE_DUAL_STACK at the
		// task level; both KinD jobs must inherit it.
		n := 0
		for _, j := range jobs {
			if j.Env["PROVISIONER"] == "local-kind" {
				n++
				if j.Env["ENABLE_DUAL_STACK"] != "true" {
					t.Errorf("KinD job %q: ENABLE_DUAL_STACK=%q, want true (block task env)", j.Job, j.Env["ENABLE_DUAL_STACK"])
				}
			}
		}
		if n != 2 {
			t.Errorf("local-kind jobs = %d, want 2", n)
		}
	})
}

func TestCartesianOrder(t *testing.T) {
	axes := []Axis{
		{EnvVar: "A", Values: []string{"1", "2"}},
		{EnvVar: "B", Values: []string{"x", "y"}},
	}
	got := cartesian(axes)
	if len(got) != 4 {
		t.Fatalf("cartesian len = %d, want 4", len(got))
	}
	// Source order, last axis fastest: (1,x)(1,y)(2,x)(2,y).
	want := []map[string]string{
		{"A": "1", "B": "x"},
		{"A": "1", "B": "y"},
		{"A": "2", "B": "x"},
		{"A": "2", "B": "y"},
	}
	for i, w := range want {
		for k, v := range w {
			if got[i][k] != v {
				t.Errorf("combo %d: %s=%q, want %q", i, k, got[i][k], v)
			}
		}
	}
}
