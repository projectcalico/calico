// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package driver

import (
	"context"
	"testing"

	csi "github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNodePublishVolumeMissingPodInfoMessage(t *testing.T) {
	ns := newNodeService(nil)
	_, err := ns.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{VolumeId: "volume", TargetPath: "/unused"})
	want := "Could not extract pod information: missing the required pod info: pod.name: , pod.namespace: , pod.uid: , serviceAccount.name: "
	if status.Code(err) != codes.Internal || status.Convert(err).Message() != want {
		t.Fatalf("unexpected error: %v", err)
	}
}
