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

package hashutils

import (
	"crypto/sha256"
	"encoding/base64"
)

const shortenedPrefix = "_"

// GetLengthLimitedID returns an ID that consists of the given prefix and, either the given suffix,
// or, if that would exceed the length limit, a cryptographic hash of the suffix, truncated to the
// required length.
func GetLengthLimitedID(fixedPrefix, suffix string, maxLength int) string {
	prefixLen := len(fixedPrefix)
	suffixLen := len(suffix)
	totalLen := prefixLen + suffixLen
	if totalLen > maxLength || (totalLen == maxLength && suffix[0:1] == shortenedPrefix) {
		// Either it's just too long, or it's exactly the right length but it happens to
		// start with the character that we use to denote a shortened string, which could
		// result in a clash.  Hash the value and truncate...
		hasher := sha256.New()
		hasher.Write([]byte(suffix))
		hash := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
		charsLeftForHash := maxLength - 1 - prefixLen
		return fixedPrefix + shortenedPrefix + hash[0:charsLeftForHash]
	}
	// No need to shorten.
	return fixedPrefix + suffix
}
