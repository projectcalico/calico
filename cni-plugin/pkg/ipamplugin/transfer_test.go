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

package ipamplugin

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// stubIPAM answers the two calls transferFromPriorSandbox makes. The embedded nil interface
// panics if the code under test calls anything else.
type stubIPAM struct {
	ipam.Interface
	attr    *model.AllocationAttribute
	moveErr error
	moves   int
}

func (s *stubIPAM) GetAssignmentAttributes(context.Context, cnet.IP) (*model.AllocationAttribute, error) {
	return s.attr, nil
}

func (s *stubIPAM) MoveIPToHandle(context.Context, cnet.IP, ipam.MoveOptions) error {
	s.moves++
	return s.moveErr
}

func ownerAttrs(pod string) map[string]string {
	return map[string]string{
		ipam.AttributeNamespace: "ns",
		ipam.AttributePod:       pod,
	}
}

func transferOnce(ipamClient ipam.Interface) error {
	epIDs := &utils.WEPIdentifiers{Namespace: "ns"}
	epIDs.Pod = "web-0"
	logger := logrus.WithField("test", "transfer")
	return transferFromPriorSandbox(context.Background(), ipamClient, net.ParseIP("10.0.0.5"), "calico-uts.sandbox-y", nil, "calico-uts", epIDs, time.Now(), logger)
}

func TestTransferFromPriorSandboxMoveFailureIsNotAddressNotHeld(t *testing.T) {
	RegisterTestingT(t)

	handle := ipam.PodHandleID("calico-uts", "sandbox-x")
	stub := &stubIPAM{
		attr: &model.AllocationAttribute{
			HandleID:         &handle,
			ActiveOwnerAttrs: ownerAttrs("web-0"),
		},
		moveErr: errors.New("ownership changed between read and move"),
	}

	err := transferOnce(stub)

	Expect(err).To(HaveOccurred())
	Expect(stub.moves).To(Equal(1))
	var cniErr *cnitypes.Error
	Expect(errors.As(err, &cniErr)).To(BeFalse(), "a failed move is transient, got CNI error: %v", err)
}

func TestTransferFromPriorSandboxAddressNotHeld(t *testing.T) {
	handle := ipam.PodHandleID("calico-uts", "sandbox-x")
	for name, attr := range map[string]*model.AllocationAttribute{
		"no attributes": nil,
		"no handle":     {},
		"a non-pod handle": {
			HandleID: new(string),
		},
		"another pod": {
			HandleID:         &handle,
			ActiveOwnerAttrs: ownerAttrs("other"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			RegisterTestingT(t)
			stub := &stubIPAM{attr: attr}

			err := transferOnce(stub)

			var cniErr *cnitypes.Error
			Expect(errors.As(err, &cniErr)).To(BeTrue(), "expected a CNI error, got: %v", err)
			Expect(cniErr.Code).To(BeEquivalentTo(types.ErrCodeAddressNotHeld))
			Expect(stub.moves).To(BeZero())
		})
	}
}
