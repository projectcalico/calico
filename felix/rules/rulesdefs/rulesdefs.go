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

// Package rulesdefs holds the names Felix writes into the dataplane, for the dataplane packages
// that need to recognise them but can't import felix/rules because it imports them.
package rulesdefs

// RuleHashPrefix prefixes the hash Felix writes into the comment on every rule it owns.
const RuleHashPrefix = "cali:"

// SharedTables are the tables Calico shares with everything else on the node. Both iptables
// backends write into their own copies of these.
var SharedTables = []string{"filter", "nat", "mangle", "raw"}

// AllHistoricChainNamePrefixes lists all the prefixes that we've used for chains.  Keeping
// track of the old names lets us clean them up.
var AllHistoricChainNamePrefixes = []string{
	// Current.
	"cali-",

	// Early RCs of Felix 2.1 used "cali" as the prefix for some chains rather than
	// "cali-".  This led to name clashes with the DHCP agent, which uses "calico-" as
	// its prefix.  We need to explicitly list these exceptions.
	"califw-",
	"calitw-",
	"califh-",
	"calith-",
	"calipi-",
	"calipo-",

	// Pre Felix v2.1.
	"felix-",
}
