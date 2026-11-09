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
	"path/filepath"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/gofrs/flock"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	releaseNetwork     = "calico-uts"
	releaseNamespace   = "ns"
	releaseContainerID = "sandbox-y"
)

var (
	errReleaseLookup = errors.New("datastore down")
	errReleaseIPs    = errors.New("release failed")
)

// stubClient is a Calico client that serves a stub IPAM. Other methods panic through the nil
// embedded interface.
type stubClient struct {
	client.Interface
	ipam ipam.Interface
}

func (c stubClient) IPAM() ipam.Interface {
	return c.ipam
}

// releaseStubIPAM serves IPsByHandle from a fixed map and records what ReleaseIPs and
// ReleaseByHandle are asked to release. A handle missing from the map does not exist. Each call
// records whether its context has a deadline and, when lockPath is set, whether that lock was
// held. Other methods panic through the nil embedded interface.
type releaseStubIPAM struct {
	ipam.Interface
	handleIPs       map[string][]string
	ipsErr          error
	releaseErr      error
	released        []ipam.ReleaseOptions
	releasedHandles []string
	lockPath        string
	hasDeadline     []bool
	lockHeld        []bool
}

func (s *releaseStubIPAM) IPsByHandle(ctx context.Context, handleID string) ([]cnet.IP, error) {
	s.observe(ctx)
	if s.ipsErr != nil {
		return nil, s.ipsErr
	}
	addrs, ok := s.handleIPs[handleID]
	if !ok {
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: handleID}
	}
	var ips []cnet.IP
	for _, a := range addrs {
		ips = append(ips, cnet.IP{IP: net.ParseIP(a)})
	}
	return ips, nil
}

func (s *releaseStubIPAM) ReleaseIPs(ctx context.Context, opts ...ipam.ReleaseOptions) ([]cnet.IP, []ipam.ReleaseOptions, error) {
	s.observe(ctx)
	s.released = append(s.released, opts...)
	return nil, nil, s.releaseErr
}

func (s *releaseStubIPAM) ReleaseByHandle(ctx context.Context, handleID string) error {
	s.observe(ctx)
	s.releasedHandles = append(s.releasedHandles, handleID)
	if _, ok := s.handleIPs[handleID]; !ok {
		return cerrors.ErrorResourceDoesNotExist{Identifier: handleID}
	}
	return nil
}

func (s *releaseStubIPAM) observe(ctx context.Context) {
	_, ok := ctx.Deadline()
	s.hasDeadline = append(s.hasDeadline, ok)
	if s.lockPath != "" {
		lock := flock.New(s.lockPath)
		locked, err := lock.TryLock()
		Expect(err).NotTo(HaveOccurred())
		if locked {
			Expect(lock.Unlock()).To(Succeed())
		}
		s.lockHeld = append(s.lockHeld, !locked)
	}
}

// releasedAddresses returns the addresses ReleaseIPs was asked for, checking each was on handle.
func (s *releaseStubIPAM) releasedAddresses(handle string) []string {
	var out []string
	for _, opt := range s.released {
		Expect(opt.Handle).To(Equal(handle))
		out = append(out, opt.Address)
	}
	return out
}

// releaseSandbox runs ReleaseSandbox for pod's sandbox-y with stub. The pod rides on the
// context as the calling plugin passes it, so VMI detection reads it from there.
func releaseSandbox(t *testing.T, stub *releaseStubIPAM, pod string, keep ...string) error {
	t.Helper()
	conf := types.NetConf{Name: releaseNetwork, Nodename: "node1", IPAMLockFile: filepath.Join(t.TempDir(), "ipam.lock")}
	if stub.lockPath != "" {
		conf.IPAMLockFile = stub.lockPath
	}
	args := &skel.CmdArgs{
		ContainerID: releaseContainerID,
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=" + releaseNamespace + ";K8S_POD_NAME=" + pod,
	}
	var keepAddresses []net.IP
	for _, k := range keep {
		keepAddresses = append(keepAddresses, net.ParseIP(k))
	}
	ctx := utils.WithSandboxLookups(context.Background(), utils.SandboxLookups{
		Pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod, Namespace: releaseNamespace}},
	})
	return ReleaseSandbox(ctx, stubClient{ipam: stub}, conf, args, keepAddresses)
}

func TestReleaseSandboxWithNothingToKeepReleasesBothHandles(t *testing.T) {
	RegisterTestingT(t)
	handle := ipam.PodHandleID(releaseNetwork, releaseContainerID)
	stub := &releaseStubIPAM{handleIPs: map[string][]string{handle: {"10.0.0.5"}}}

	Expect(releaseSandbox(t, stub, "web-0")).To(Succeed())

	Expect(stub.releasedHandles).To(Equal([]string{handle, releaseNamespace + ".web-0"}))
	Expect(stub.released).To(BeEmpty())
}

// keepCase is one ReleaseSandbox scenario with addresses to keep: what the sandbox's handle
// holds, how IPAM answers, and what should be released and returned.
type keepCase struct {
	handleIPs    []string
	missing      bool
	ipsErr       error
	releaseErr   error
	keep         []string
	wantReleased []string
	wantErr      error
}

func TestReleaseSandboxWithAddressesToKeep(t *testing.T) {
	handle := ipam.PodHandleID(releaseNetwork, releaseContainerID)
	for name, c := range map[string]keepCase{
		"releases each unlisted address and keeps the listed one": {
			handleIPs: []string{"10.0.0.5", "10.0.0.6", "fd00::6"}, keep: []string{"10.0.0.5"},
			wantReleased: []string{"10.0.0.6", "fd00::6"},
		},
		"matches a kept address by IP, not spelling": {
			handleIPs: []string{"fd00:0:0::5", "fd00::6"}, keep: []string{"fd00::5"},
			wantReleased: []string{"fd00::6"},
		},
		"releases nothing when the handle holds only kept addresses": {
			handleIPs: []string{"10.0.0.5"}, keep: []string{"10.0.0.5"},
		},
		"treats a missing handle as nothing to release": {
			missing: true, keep: []string{"10.0.0.5"},
		},
		"returns a handle lookup error": {
			ipsErr: errReleaseLookup, keep: []string{"10.0.0.5"},
			wantErr: errReleaseLookup,
		},
		"returns a release error after trying every unlisted address": {
			handleIPs: []string{"10.0.0.6", "10.0.0.7"}, releaseErr: errReleaseIPs, keep: []string{"10.0.0.5"},
			wantReleased: []string{"10.0.0.6", "10.0.0.7"}, wantErr: errReleaseIPs,
		},
	} {
		t.Run(name, func(t *testing.T) {
			RegisterTestingT(t)
			stub := &releaseStubIPAM{handleIPs: map[string][]string{}, ipsErr: c.ipsErr, releaseErr: c.releaseErr}
			if !c.missing {
				stub.handleIPs[handle] = c.handleIPs
			}

			err := releaseSandbox(t, stub, "web-0", c.keep...)

			if c.wantErr != nil {
				Expect(err).To(MatchError(c.wantErr))
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
			Expect(stub.releasedHandles).To(BeEmpty(), "released a whole handle")
			Expect(stub.releasedAddresses(handle)).To(ConsistOf(c.wantReleased))
		})
	}
}

func TestReleaseSandboxKeepsAddressesForAVirtLauncherPodThatIsNotAVM(t *testing.T) {
	RegisterTestingT(t)
	handle := ipam.PodHandleID(releaseNetwork, releaseContainerID)
	stub := &releaseStubIPAM{handleIPs: map[string][]string{handle: {"10.0.0.5", "10.0.0.6"}}}

	Expect(releaseSandbox(t, stub, "virt-launcher-vm1-abcde", "10.0.0.5")).To(Succeed())

	Expect(stub.releasedHandles).To(BeEmpty(), "released a whole handle")
	Expect(stub.releasedAddresses(handle)).To(ConsistOf("10.0.0.6"))
}

func TestReleaseSandboxReleasesNothingForADeletedVirtLauncherPod(t *testing.T) {
	RegisterTestingT(t)
	handle := ipam.PodHandleID(releaseNetwork, releaseContainerID)
	stub := &releaseStubIPAM{handleIPs: map[string][]string{handle: {"10.0.0.6"}}}
	conf := types.NetConf{Name: releaseNetwork, Nodename: "node1", IPAMLockFile: filepath.Join(t.TempDir(), "ipam.lock")}
	args := &skel.CmdArgs{
		ContainerID: releaseContainerID,
		IfName:      "eth0",
		Args:        "K8S_POD_NAMESPACE=" + releaseNamespace + ";K8S_POD_NAME=virt-launcher-vm1-abcde",
	}
	ctx := utils.WithSandboxLookups(context.Background(), utils.SandboxLookups{K8sClient: k8sfake.NewSimpleClientset()})

	Expect(ReleaseSandbox(ctx, stubClient{ipam: stub}, conf, args, nil)).To(Succeed())

	Expect(stub.releasedHandles).To(BeEmpty())
	Expect(stub.released).To(BeEmpty())
}

func TestReleaseSandboxHoldsTheIPAMLockWithADeadline(t *testing.T) {
	handle := ipam.PodHandleID(releaseNetwork, releaseContainerID)
	for name, keep := range map[string][]string{
		"releasing whole handles":      nil,
		"releasing unlisted addresses": {"10.0.0.5"},
	} {
		t.Run(name, func(t *testing.T) {
			RegisterTestingT(t)
			lockPath := filepath.Join(t.TempDir(), "ipam.lock")
			stub := &releaseStubIPAM{handleIPs: map[string][]string{handle: {"10.0.0.6"}}, lockPath: lockPath}

			Expect(releaseSandbox(t, stub, "web-0", keep...)).To(Succeed())

			Expect(stub.lockHeld).NotTo(BeEmpty())
			Expect(stub.lockHeld).To(HaveEach(BeTrue()))
			Expect(stub.hasDeadline).To(HaveEach(BeTrue()))
			lock := flock.New(lockPath)
			Expect(lock.TryLock()).To(BeTrue(), "the lock is still held")
			Expect(lock.Unlock()).To(Succeed())
		})
	}
}
