// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

const (
	DefaultStatusFile = "/status/status.json"
)

type ConditionStatus struct {
	Ready  bool
	Reason string
}

type Status struct {
	Readiness  map[string]ConditionStatus
	readyMutex sync.Mutex
	statusFile string
}

func New(file string) *Status {
	st := Status{
		statusFile: file,
		Readiness:  map[string]ConditionStatus{},
	}
	return &st
}

// SetReady sets the status of one ready key and the reason associated with that status.
func (s *Status) SetReady(key string, ready bool, reason string) {
	s.readyMutex.Lock()
	defer s.readyMutex.Unlock()

	if prev, ok := s.Readiness[key]; !ok || prev.Ready != ready || prev.Reason != reason {
		fields := logrus.Fields{
			"prev.Ready":  prev.Ready,
			"ready":       ready,
			"prev.Reason": prev.Reason,
			"reason":      reason,
		}
		logrus.WithFields(fields).Debug("Updating readiness status")
		s.Readiness[key] = ConditionStatus{Ready: ready, Reason: reason}
		if err := s.writeStatus(); err != nil {
			logrus.WithError(err).Warnf("Failed to write status")
		}

	}
}

// GetReady check the status of the specified ready key, if the key has never
// been set then it is considered not ready (false).
func (s *Status) GetReady(key string) bool {
	s.readyMutex.Lock()
	defer s.readyMutex.Unlock()

	v, ok := s.Readiness[key]
	if !ok {
		return false
	}
	return v.Ready
}

// GetReadiness checks all readiness keys and returns true if all are ready.
// If there are no readiness conditions then it has not been initialized and
// is considered not ready.
func (s *Status) GetReadiness() bool {
	s.readyMutex.Lock()
	defer s.readyMutex.Unlock()

	if len(s.Readiness) == 0 {
		return false
	}
	for _, v := range s.Readiness {
		if !v.Ready {
			return false
		}
	}
	return true
}

// GetNotReadyConditions cycles through all readiness keys and for any that
// are not ready the reasons are combined and returned.
// The output format is '<reason 1>; <reason 2>'.
func (s *Status) GetNotReadyConditions() string {
	s.readyMutex.Lock()
	defer s.readyMutex.Unlock()

	var unready []string
	for _, v := range s.Readiness {
		if !v.Ready {
			unready = append(unready, v.Reason)
		}
	}
	return strings.Join(unready, "; ")

}

// writeStatus writes out the status in json format.
// Lock should be held by caller.
func (s *Status) writeStatus() error {
	b, err := json.Marshal(s)
	if err != nil {
		logrus.Errorf("Failed to marshal readiness: %s", err)
		return err
	}

	// Make sure the directory exists.
	if err := os.MkdirAll(filepath.Dir(s.statusFile), os.ModePerm); err != nil {
		logrus.Errorf("Failed to prepare directory: %s", err)
		return err
	}

	// Write the file.
	err = os.WriteFile(s.statusFile, b, 0644)
	if err != nil {
		logrus.Errorf("Failed to write readiness file: %s", err)
		return err
	}

	return nil
}

// ReadStatusFile reads in the status file as written by WriteStatus.
func ReadStatusFile(file string) (*Status, error) {
	st := &Status{}
	contents, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(contents, st)
	if err != nil {
		return nil, err
	}

	return st, nil
}
