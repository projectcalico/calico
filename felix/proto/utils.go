// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package proto

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/gogo/protobuf/types"
)

// ConvertTime converts a time.Time structure into gogo types Timestamp
func ConvertTime(time time.Time) *types.Timestamp {
	var val, err = types.TimestampProto(time)
	if err != nil {
		log.WithError(err).Panic("Failed to convert time to timestamp")
	}
	return val
}

// ConvertTimestamp converts a gogo types Timestamp structure into a time.Time
func ConvertTimestamp(timestamp *types.Timestamp) time.Time {
	var val, err = types.TimestampFromProto(timestamp)
	if err != nil {
		log.WithError(err).Panic("Failed to convert timestamp to time")
	}
	return val
}
