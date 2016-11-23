// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package iptables

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"strings"
)

type MatchCriteria []string

func Match() MatchCriteria {
	return nil
}

func (m MatchCriteria) Render() string {
	return strings.Join([]string(m), " ")
}

func (m MatchCriteria) String() string {
	return m.Render()
}

func (m MatchCriteria) MarkClear(mark uint32) MatchCriteria {
	if mark == 0 {
		log.Panic("Probably bug: zero mark")
	}
	return append(m, fmt.Sprintf("-m mark --mark 0/%x", mark))
}

func (m MatchCriteria) MarkSet(mark uint32) MatchCriteria {
	if mark == 0 {
		log.Panic("Probably bug: zero mark")
	}
	return append(m, fmt.Sprintf("-m mark --mark %x/%x", mark, mark))
}

func (m MatchCriteria) InInterface(ifaceMatch string) MatchCriteria {
	return append(m, fmt.Sprintf("--in-interface %s", ifaceMatch))
}

func (m MatchCriteria) OutInterface(ifaceMatch string) MatchCriteria {
	return append(m, fmt.Sprintf("--out-interface %s", ifaceMatch))
}

func (m MatchCriteria) ConntrackState(stateNames string) MatchCriteria {
	return append(m, fmt.Sprintf("-m conntrack --ctstate %s", stateNames))
}
