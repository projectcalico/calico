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

// Package nftrender renders Calico's rules into nftables syntax: the match
// builder, the action types, and the naming helpers that felix/rules uses to
// build nftables-flavoured rules.
//
// It is deliberately free of sigs.k8s.io/knftables, which reaches Linux-only
// netlink code. That keeps this package buildable for Windows, where the
// sibling felix/nftables driver cannot go. See felix/DESIGN.md.
package nftrender

import "strings"

// MaxChainNameLength is the longest chain name nftables accepts. It mirrors
// knftables.NameLengthMax, spelled out here to keep this package free of that
// import; felix/nftables asserts the two stay equal.
const MaxChainNameLength = 256

// LegalizeSetName makes an IP set name usable as an nftables set name, which
// may not contain a colon.
func LegalizeSetName(setName string) string {
	return strings.ReplaceAll(setName, ":", "-")
}
