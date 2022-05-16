// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

// Copyright (c) 2020  All rights reserved.

package tc

import (
	"testing"

	. "github.com/onsi/gomega"
)

const tcQdiscExample = `qdisc noqueue 0: dev lo root refcnt 2 
qdisc mq 0: dev ens4 root 
qdisc fq_codel 0: dev ens4 parent :4 limit 10240p flows 1024 quantum 1514 target 5.0ms interval 100.0ms memory_limit 32Mb ecn 
qdisc fq_codel 0: dev ens4 parent :3 limit 10240p flows 1024 quantum 1514 target 5.0ms interval 100.0ms memory_limit 32Mb ecn 
qdisc fq_codel 0: dev ens4 parent :2 limit 10240p flows 1024 quantum 1514 target 5.0ms interval 100.0ms memory_limit 32Mb ecn 
qdisc fq_codel 0: dev ens4 parent :1 limit 10240p flows 1024 quantum 1514 target 5.0ms interval 100.0ms memory_limit 32Mb ecn 
qdisc clsact ffff: dev ens4 parent ffff:fff1 
qdisc noqueue 0: dev docker0 root refcnt 2 
qdisc noqueue 0: dev tunl0 root refcnt 2 
qdisc clsact ffff: dev tunl0 parent ffff:fff1 
qdisc noqueue 0: dev calid5ce5b5565b root refcnt 2 
qdisc clsact ffff: dev calid5ce5b5565b parent ffff:fff1 
`

func TestFindClsactQdiscs(t *testing.T) {
	RegisterTestingT(t)
	Expect(findClsactQdiscs([]byte(tcQdiscExample))).To(ConsistOf("ens4", "tunl0", "calid5ce5b5565b"))
}

const tcFilterExample = `filter protocol all pref 49152 bpf chain 0 
filter protocol all pref 49152 bpf chain 0 handle 0x1 from_wep_info.o:[calico_from_workload_ep] direct-action not_in_hw id 210 tag 79b467cf6a77fb7c jited 
filter foo bar baz biff id 1234
filter protocol all pref 49152 bpf chain 0 handle 0x1 from_wep_info.o:[calico_from_workload_ep] direct-action not_in_hw id 313 tag 79b467cf6a77fb7c jited 
`

func TestParseTCFilter(t *testing.T) {
	RegisterTestingT(t)
	Expect(findBPFProgIDs([]byte(tcFilterExample))).To(ConsistOf(210, 313))
}
