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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	csi "github.com/container-storage-interface/spec/lib/go/csi"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	// TODO: move the object in here to a common package
	"github.com/projectcalico/calico/pod2daemon/flexvol/creds"
)

// Define the nodeService as per the CSI spec.
type nodeService struct {
	config *ConfigurationOptions
}

func newNodeService(cfg *ConfigurationOptions) nodeService {
	return nodeService{
		config: cfg,
	}
}

func (ns *nodeService) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	// Not needed
	return &csi.NodeStageVolumeResponse{}, nil
}

func (ns *nodeService) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	// Not needed
	return &csi.NodeUnstageVolumeResponse{}, nil
}

func (ns *nodeService) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	if req.VolumeId == "" {
		log.Error("Volume ID not provided")
		return nil, status.Error(codes.InvalidArgument, "Volume ID not provided")
	}

	if len(req.TargetPath) == 0 {
		log.Error("Target path not provided")
		return nil, status.Error(codes.InvalidArgument, "Target path not provided")
	}

	// Extract the pod info from the request.
	podInfo, err := extractPodInfo(req)
	if err != nil {
		log.Errorf("Could not extract pod info: %v", err)
	}

	// Mount in the relevant directories at the TargetPath
	err = ns.mount(req.TargetPath, req.VolumeId)
	if err != nil {
		log.Errorf("Could not bind mount %s to /var/run/nodeagent/mount/%s", req.TargetPath, req.VolumeId)
		return nil, status.Errorf(codes.Internal, "Could not bind mount %s to /var/run/nodeagent/mount/%s : %v", req.TargetPath, req.VolumeId, err)
	}

	// Create a credentials file that will store the pod info for the volume. This is important for the nodeagent to watch specific pods.
	// store all of the podInfo in a file in /var/run/nodeagent/creds/volumeID
	// Volume ID should be unique for every pod since we will be creating inline ephemeral volumes.
	err = ns.addCredentialFile(req.VolumeId, podInfo)
	if err != nil {
		log.Error("Could not write pod/volume information")
		return nil, status.Errorf(codes.Internal, "Could not write pod/volume information: %v", err)
	}

	log.Infof("Mounted nodeagent UDS for pod name: %s, pod UID: %s, volume ID: %s", podInfo.Workload, podInfo.UID, req.VolumeId)
	return &csi.NodePublishVolumeResponse{}, nil
}

func (ns *nodeService) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	// Check that the required inputs are still provided.
	if req.VolumeId == "" {
		log.Error("Volume ID not provided")
		return nil, status.Error(codes.InvalidArgument, "Volume ID not provided")
	}

	if len(req.TargetPath) == 0 {
		log.Error("Target path not provided")
		return nil, status.Error(codes.InvalidArgument, "Target path not provided")
	}

	// Inspect the file stored at /var/run/nodeagent/creds/volumeID for the pod info
	podInfo, err := ns.retrievePodInfoFromFile(req.VolumeId)
	if err != nil {
		log.Error("Unable to retrieve pod info")
		return nil, status.Error(codes.Internal, "Unable to retrieve pod info")
	}

	// Unmount the relevant directories at the TargetPath
	if err = ns.unmount(req.TargetPath, req.VolumeId); err != nil {
		log.Errorf("Could not unmount volumes stored at %s", req.TargetPath)
		return nil, status.Errorf(codes.Internal, "Could not unmount volumes stored at %s: %v", req.TargetPath, err)
	}

	// Clean up the file storing the pod info.
	if err = ns.removeCredentialFile(req.VolumeId); err != nil {
		log.Errorf("Could not remove pod info file at %s/%s", ns.config.NodeAgentCredentialsHomeDir, req.VolumeId)
		return nil, status.Errorf(codes.Internal, "Could not remove pod info file at %s/%s", ns.config.NodeAgentCredentialsHomeDir, req.VolumeId)
	}

	log.Infof("Unmounted nodeagent UDS for pod name: %s, pod UID: %s, volume ID: %s", podInfo.Workload, podInfo.UID, req.VolumeId)
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func (ns *nodeService) NodeGetVolumeStats(ctx context.Context, req *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	// Not needed since we are not actually creating a real volume.
	return &csi.NodeGetVolumeStatsResponse{}, nil
}

func (ns *nodeService) NodeExpandVolume(ctx context.Context, req *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	// Not needed since we are not actually creating a real volume.
	return &csi.NodeExpandVolumeResponse{}, nil
}

func (ns *nodeService) NodeGetCapabilities(ctx context.Context, req *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	// Nothing is returned since no extra capabilities are required in order to publish/unpublish volumes.
	return &csi.NodeGetCapabilitiesResponse{}, nil
}

func (ns *nodeService) NodeGetInfo(ctx context.Context, req *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	// We return an empty response since this should not be needed since our "volumes" will be inline ephemeral volumes
	// and the controller will not publish/unpublish volumes, only the node service.
	return &csi.NodeGetInfoResponse{
		NodeId: ns.config.NodeID,
	}, nil
}

func extractPodInfo(req *csi.NodePublishVolumeRequest) (*creds.Credentials, error) {
	// Extract the relevant pod info from the VolumeContext. This requires podInfoOnMount to be set for the CSI Driver object.
	podName, podNameExists := req.VolumeContext["csi.storage.k8s.io/pod.name"]
	podNamespace, podNamespaceExists := req.VolumeContext["csi.storage.k8s.io/pod.namespace"]
	podUID, podUIDExists := req.VolumeContext["csi.storage.k8s.io/pod.uid"]
	svcAcct, svcAcctExists := req.VolumeContext["csi.storage.k8s.io/serviceAccount.name"]

	if !(podNameExists && podNamespaceExists && podUIDExists && svcAcctExists) {
		return nil, fmt.Errorf("Missing the required pod info: pod.name: %s, pod.namespace: %s, pod.uid: %s, serviceAccount.name: %s", podName, podNamespace, podUID, svcAcct)
	}

	return &creds.Credentials{
		Workload:       podName,
		UID:            podUID,
		Namespace:      podNamespace,
		ServiceAccount: svcAcct,
	}, nil
}

func (ns *nodeService) mount(destinationDir, volumeId string) error {
	// bind destinationDir/nodeagent to /var/run/nodeagent/mount/volumeId
	newDir := ns.config.NodeAgentWorkloadHomeDir + "/" + volumeId
	err := os.MkdirAll(newDir, 0777)
	if err != nil {
		log.Errorf("Mount error: failed to create directory %s: %v", newDir, err)
		return err
	}

	// Create the mount volume directory in /var/lib/kubelet/pods/<UID>/volumes/kubernetes.io~csi
	err = os.MkdirAll(destinationDir, 0777)
	if err != nil {
		log.Errorf("Mount error: failed to create directory %s: %v", destinationDir, err)
		return err
	}

	// Not really needed but attempt to workaround:
	// https://github.com/kubernetes/kubernetes/blob/61ac9d46382884a8bd9e228da22bca5817f6d226/pkg/util/mount/mount_linux.go
	// Run "mount -t tmpfs -o size=8K tmpfs destinationDir"
	if err := syscall.Mount("tmpfs", destinationDir, "tmpfs", syscall.O_RDWR|syscall.MS_RELATIME, "size=8K"); err != nil {
		os.RemoveAll(newDir)
		log.Errorf("Could not mount tmpfs to %s: %v", destinationDir, err)
		return err
	}

	newDestinationDir := destinationDir + "/nodeagent"
	err = os.MkdirAll(newDestinationDir, 0777)
	if err != nil {
		// Run "umount destinationDir"
		e := syscall.Unmount(destinationDir, 0)
		if e != nil {
			log.Errorf("Mount error: failed to unmount %s: %v", destinationDir, e)
		}
		e = os.RemoveAll(newDir)
		if e != nil {
			log.Errorf("Mount error: failed to clear %s: %v", newDir, e)
		}
		log.Errorf("Failed to create nodeagent directory at %s: %v", newDestinationDir, err)
		return err
	}

	// Do a bind mount
	// Run "mount --bind newDir newDestinationDir"
	err = syscall.Mount(newDir, newDestinationDir, "", syscall.MS_BIND, "")
	if err != nil {
		// Run "umount destinationDir"
		e := syscall.Unmount(destinationDir, 0)
		if e != nil {
			log.Errorf("Mount error: failed to unmount %s: %v", destinationDir, e)
		}
		e = os.RemoveAll(newDir)
		if e != nil {
			log.Errorf("Mount error: failed to clear %s: %v", newDir, e)
		}
		log.Errorf("Failed to bind mount %s to %s: %v", newDir, newDestinationDir, err)
		return err
	}

	return nil
}

func (ns *nodeService) addCredentialFile(volumeID string, podInfo *creds.Credentials) error {
	//Make the directory and then write the podInfo as json to it.
	err := os.MkdirAll(ns.config.NodeAgentCredentialsHomeDir, 0755)
	if err != nil {
		return err
	}

	var attrs []byte
	attrs, err = json.Marshal(podInfo)
	if err != nil {
		return err
	}

	credsFileTmp := strings.Join([]string{ns.config.NodeAgentManagementHomeDir, volumeID + ".json"}, "/")
	_ = ioutil.WriteFile(credsFileTmp, attrs, 0644)

	// Move it to the right location now.
	credsFile := strings.Join([]string{ns.config.NodeAgentCredentialsHomeDir, volumeID + ".json"}, "/")
	return os.Rename(credsFileTmp, credsFile)
}

func (ns *nodeService) removeCredentialFile(volumeId string) error {
	credsFile := strings.Join([]string{ns.config.NodeAgentCredentialsHomeDir, volumeId + ".json"}, "/")
	err := os.Remove(credsFile)
	return err
}

func (ns *nodeService) retrievePodInfoFromFile(volumeId string) (*creds.Credentials, error) {
	credsFilePath := strings.Join([]string{ns.config.NodeAgentCredentialsHomeDir, volumeId + ".json"}, "/")

	credsFile, err := os.Open(credsFilePath)
	if err != nil {
		return nil, err
	}

	defer credsFile.Close()

	credsFileBytes, err := ioutil.ReadAll(credsFile)
	if err != nil {
		return nil, err
	}

	podInfo := creds.Credentials{}
	err = json.Unmarshal(credsFileBytes, &podInfo)
	if err != nil {
		return nil, err
	}

	return &podInfo, nil
}

func (ns *nodeService) unmount(dir, volumeId string) error {
	// unmount the bind mount
	err := unmount(dir + "/nodeagent")
	if err != nil {
		log.Errorf("Unmount error: failed to unmount %s/nodeagent: %v", dir, err)
	}

	// unmount the tmpfs
	err = unmount(dir)
	if err != nil {
		log.Errorf("Unmount error: failed to unmount %s: %v", dir, err)
	}

	// delete the directory that was created.
	delDir := strings.Join([]string{ns.config.NodeAgentWorkloadHomeDir, volumeId}, "/")
	err = os.RemoveAll(delDir)
	if err != nil {
		log.Errorf("Unmount error: unable to remove mount directory %s: %v", delDir, err)
		return err
	}

	return nil
}

func unmount(dir string) error {
	err := syscall.Unmount(dir, 0)
	if err != nil {
		return err
	}

	return nil
}
