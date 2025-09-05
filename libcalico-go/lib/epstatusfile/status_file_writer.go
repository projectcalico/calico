// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package epstatusfile

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

const (
	dirStatus  = "endpoint-status"
	statusUp   = "up"
	statusDown = "down"
)

func GetDirStatus() string {
	return dirStatus
}

// EndpointStatusFileWriter writes workload endpoint statuses to the file system.
type EndpointStatusFileWriter struct {
	statusDirPrefix string

	Filesys
}

type Filesys interface {
	Create(name string) (*os.File, error)
	Remove(name string) error
	Mkdir(name string, perm os.FileMode) error
	ReadDir(name string) ([]os.DirEntry, error)
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm os.FileMode) error
}

type defaultFilesys struct{}

// Create wraps os.Create.
func (fs *defaultFilesys) Create(name string) (*os.File, error) {
	return os.Create(name)
}

// Remove wraps os.Remove.
func (fs *defaultFilesys) Remove(name string) error {
	return os.Remove(name)
}

// Mkdir wraps os.Mkdir.
func (fs *defaultFilesys) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(name, perm)
}

// ReadDir wraps os.ReadDir.
func (fs *defaultFilesys) ReadDir(name string) ([]os.DirEntry, error) {
	return os.ReadDir(name)
}

// ReadFile wraps os.ReadFile.
func (fs *defaultFilesys) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

// WriteFile wraps os.WriteFile.
func (fs *defaultFilesys) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}

// NewEndpointStatusFileWriter creates a new EndpointStatusFileWriter.
func NewEndpointStatusFileWriter(statusDirPath string) *EndpointStatusFileWriter {
	return NewEndpointStatusFileWriterWithShims(statusDirPath, &defaultFilesys{})
}

func NewEndpointStatusFileWriterWithShims(statusDirPath string, filesys Filesys) *EndpointStatusFileWriter {
	return &EndpointStatusFileWriter{
		statusDirPrefix: statusDirPath,

		Filesys: filesys,
	}
}

func (w *EndpointStatusFileWriter) WriteStatusFile(name string, epStatusJSON string) error {
	// Write file to dir.
	logrus.WithField("filename", name).Debug("Writing endpoint-status file to status-dir")
	filename := filepath.Join(w.statusDirPrefix, dirStatus, name)

	return w.Filesys.WriteFile(filename, []byte(epStatusJSON), 0644)
}

func (w *EndpointStatusFileWriter) DeleteStatusFile(name string) error {
	filename := filepath.Join(w.statusDirPrefix, dirStatus, name)
	return w.Filesys.Remove(filename)
}

// EnsureStatusDir ensures there is a directory named "endpoint-status", within
// the parent dir specified by prefix. Attempts to create the dir if it doesn't exist.
// Returns all entries along with their unmarshaled WorkloadEndpointStatus structs within the dir if any exist.
func (w *EndpointStatusFileWriter) EnsureStatusDir(prefix string) ([]fs.DirEntry, []WorkloadEndpointStatus, error) {
	var presentFiles []fs.DirEntry
	var epStatuses []WorkloadEndpointStatus

	path := filepath.Join(prefix, dirStatus)

	entries, err := w.Filesys.ReadDir(path)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		// Discard ErrNotExist and return the result of attempting to create it.
		return presentFiles, epStatuses, w.Filesys.Mkdir(path, fs.FileMode(0755))
	}

	// Iterate over each file entry.
	for _, entry := range entries {
		// Skip directories, process only files.
		if entry.IsDir() {
			continue
		}

		// Construct the full file path.
		filePath := filepath.Join(path, entry.Name())
		logCxt := logrus.WithField("file", filePath)

		var epStatus WorkloadEndpointStatus

		// Read the file contents.
		// If file contents is not valid, assign an empty epStatus.
		data, err := w.Filesys.ReadFile(filePath)
		if err != nil {
			logCxt.WithError(err).Warn("Failed to read file content.")
		} else {
			// Unmarshal JSON into a struct.
			err = json.Unmarshal(data, &epStatus)
			if err != nil {
				logCxt.WithError(err).Error("Failed to unmarshal JSON")
			}
		}

		// Append entry to the slice.
		presentFiles = append(presentFiles, entry)

		// Append the parsed struct to the slice.
		epStatuses = append(epStatuses, epStatus)
	}

	return presentFiles, epStatuses, err
}

type WorkloadEndpointStatus struct {
	IfaceName   string   `json:"ifaceName,omitempty"`   // Name of the interface
	Mac         string   `json:"mac,omitempty"`         // Mac of the interface
	Ipv4Nets    []string `json:"ipv4Nets,omitempty"`    // V4 IPs of the workload
	Ipv6Nets    []string `json:"ipv6Nets,omitempty"`    // V6 IPs of the workload
	BGPPeerName string   `json:"bgpPeerName,omitempty"` // Non-empty if the workload is selected for local BGP peering.
}

func GetWorkloadEndpointStatusFromFile(filePath string) (*WorkloadEndpointStatus, error) {
	logCxt := log.WithField("file", filePath)

	// Read the file contents.
	data, err := os.ReadFile(filePath)
	if err != nil {
		logCxt.WithError(err).Error("Failed to read file content.")
		return nil, err
	}

	logCxt.WithField("content", string(data)).Debug("Endpoint status from file")

	// Unmarshal JSON into a struct.
	var epStatus WorkloadEndpointStatus
	err = json.Unmarshal(data, &epStatus)
	if err != nil {
		return nil, err
	}

	return &epStatus, nil
}
