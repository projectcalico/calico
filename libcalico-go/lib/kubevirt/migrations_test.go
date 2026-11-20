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

package kubevirt_test

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubevirtv1 "kubevirt.io/api/core/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
)

func TestMigrationVMIKey(t *testing.T) {
	m := &kubevirtv1.VirtualMachineInstanceMigration{
		ObjectMeta: metav1.ObjectMeta{Namespace: "vms", Name: "kubevirt-migrate-vm-abcde"},
		Spec:       kubevirtv1.VirtualMachineInstanceMigrationSpec{VMIName: "db"},
	}
	keys, err := kubevirt.MigrationVMIKey(m)
	if err != nil || len(keys) != 1 || keys[0] != "vms/db" {
		t.Errorf("MigrationVMIKey = %v, %v; want [vms/db]", keys, err)
	}

	keys, _ = kubevirt.MigrationVMIKey(&kubevirtv1.VirtualMachineInstanceMigration{})
	if len(keys) != 0 {
		t.Errorf("MigrationVMIKey with no VMIName = %v, want none", keys)
	}

	keys, _ = kubevirt.MigrationVMIKey(&kubevirtv1.VirtualMachineInstance{})
	if len(keys) != 0 {
		t.Errorf("MigrationVMIKey of a VMI = %v, want none", keys)
	}
}
