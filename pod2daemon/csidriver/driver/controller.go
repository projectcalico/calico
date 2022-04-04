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

	csi "github.com/container-storage-interface/spec/lib/go/csi"
)

// Define the controllerService as per the CSI spec.
type controllerService struct {
}

func newControllerService() controllerService {
	return controllerService{}
}

func (cs *controllerService) CreateVolume(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	// Not needed since we will only create inline ephemeral volumes which will only need to be handled by the node service.
	return &csi.CreateVolumeResponse{}, nil
}

func (cs *controllerService) DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	// Not needed since we will only create inline ephemeral volumes which will only need to be handled by the node service.
	return &csi.DeleteVolumeResponse{}, nil
}

func (cs *controllerService) ControllerPublishVolume(ctx context.Context, req *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
	// Not needed since we will only create inline ephemeral volumes which will only need to be handled by the node service.
	return &csi.ControllerPublishVolumeResponse{}, nil
}

func (cs *controllerService) ControllerUnpublishVolume(ctx context.Context, req *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error) {
	// Not needed since we will only create inline ephemeral volumes which will only need to be handled by the node service.
	return &csi.ControllerUnpublishVolumeResponse{}, nil
}

func (cs *controllerService) ValidateVolumeCapabilities(ctx context.Context, req *csi.ValidateVolumeCapabilitiesRequest) (*csi.ValidateVolumeCapabilitiesResponse, error) {
	// Should not need this. Only used for checking if pre-provisioned volumes match the appropriate capabilities.
	return &csi.ValidateVolumeCapabilitiesResponse{}, nil
}

func (cs *controllerService) ListVolumes(ctx context.Context, req *csi.ListVolumesRequest) (*csi.ListVolumesResponse, error) {
	// Should not need this. Only used for inspecting existing volumes and we will not create or use any.
	return &csi.ListVolumesResponse{}, nil
}

func (cs *controllerService) GetCapacity(ctx context.Context, req *csi.GetCapacityRequest) (*csi.GetCapacityResponse, error) {
	// Should not need this. Only used for validating if storage pool has enough space for the requested volume creation.
	return &csi.GetCapacityResponse{}, nil
}

func (cs *controllerService) ControllerGetCapabilities(ctx context.Context, req *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error) {
	// This is not needed since the controller does not actually need to do anything so it does not need any capabilities.
	return &csi.ControllerGetCapabilitiesResponse{}, nil
}

func (cs *controllerService) CreateSnapshot(ctx context.Context, req *csi.CreateSnapshotRequest) (*csi.CreateSnapshotResponse, error) {
	// Should not need this. We are not working with real volumes so creating a snapshot should be irrelevant.
	return &csi.CreateSnapshotResponse{}, nil
}

func (cs *controllerService) DeleteSnapshot(ctx context.Context, req *csi.DeleteSnapshotRequest) (*csi.DeleteSnapshotResponse, error) {
	// Should not need this. We are not working with real volumes so deleting snapshots should be irrelevant.
	return &csi.DeleteSnapshotResponse{}, nil
}

func (cs *controllerService) ListSnapshots(ctx context.Context, req *csi.ListSnapshotsRequest) (*csi.ListSnapshotsResponse, error) {
	// Should not need this. We are not working with real volumes or snapshots.
	return &csi.ListSnapshotsResponse{}, nil
}

func (cs *controllerService) ControllerExpandVolume(ctx context.Context, req *csi.ControllerExpandVolumeRequest) (*csi.ControllerExpandVolumeResponse, error) {
	// Should not need this. We are not working with real volumes.
	return &csi.ControllerExpandVolumeResponse{}, nil
}

func (cs *controllerService) ControllerGetVolume(ctx context.Context, req *csi.ControllerGetVolumeRequest) (*csi.ControllerGetVolumeResponse, error) {
	// Should not need this. There won't really be any conditions or status for us to show for our "volume".
	return &csi.ControllerGetVolumeResponse{}, nil
}
