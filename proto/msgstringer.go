// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package proto

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

// msgStringer wraps an API message to customise how we stringify it.  For example, it truncates
// the lists of members in the (potentially very large) IPSetsUpdate messages.
type MsgStringer struct {
	Msg interface{}
}

func (m MsgStringer) String() string {
	if log.GetLevel() < log.DebugLevel && m.Msg != nil {
		const truncateAt = 10
		switch msg := m.Msg.(type) {
		case *IPSetUpdate:
			if len(msg.Members) < truncateAt {
				return fmt.Sprintf("%v", msg)
			}
			return fmt.Sprintf("id:%#v members(%d):%#v(truncated)",
				msg.Id, len(msg.Members), msg.Members[:truncateAt])
		case *IPSetDeltaUpdate:
			if len(msg.AddedMembers) < truncateAt && len(msg.RemovedMembers) < truncateAt {
				return fmt.Sprintf("%v", msg)
			}
			addedNum := truncateAt
			removedNum := truncateAt
			if len(msg.AddedMembers) < addedNum {
				addedNum = len(msg.AddedMembers)
			}
			if len(msg.RemovedMembers) < removedNum {
				removedNum = len(msg.RemovedMembers)
			}
			return fmt.Sprintf("id:%#v addedMembers(%d):%#v(truncated) removedMembers(%d):%#v(truncated)",
				msg.Id, len(msg.AddedMembers), msg.AddedMembers[:addedNum],
				len(msg.RemovedMembers), msg.RemovedMembers[:removedNum])
		}
	}
	return fmt.Sprintf("%v", m.Msg)
}
