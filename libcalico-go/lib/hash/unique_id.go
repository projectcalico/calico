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

package hash

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"

	log "github.com/sirupsen/logrus"
)

const shortenedPrefix = "_"

// MakeUniqueID uses a secure hash to create a unique ID from content.
// The hash is prefixed with "<prefix>:".
func MakeUniqueID(prefix, content string) string {
	hash := crypto.SHA224.New()
	bytes := []byte(prefix + ":" + content)
	written, err := hash.Write(bytes)
	if err != nil {
		panic(err)
	}
	if written != len(bytes) {
		panic("Failed to write to Hash")
	}
	hashBytes := hash.Sum(make([]byte, 0, hash.Size()))
	return prefix + ":" + base64.RawURLEncoding.EncodeToString(hashBytes)
}

// GetLengthLimitedID returns an ID that consists of the given prefix and, either the given suffix,
// or, if that would exceed the length limit, a cryptographic hash of the suffix, truncated to the
// required length.
// If the combined prefix+suffix fits within maxLength, it returns the original string unchanged.
// If it's too long, it hashes the suffix using SHA256, base64-encodes it, and truncates to fit.
// Uses shortenedPrefix ("_") to indicate when a hash was used, to avoid collisions.
func GetLengthLimitedID(fixedPrefix, suffix string, maxLength int) string {
	if len(suffix) == 0 {
		suffix = shortenedPrefix
	}
	prefixLen := len(fixedPrefix)
	suffixLen := len(suffix)
	totalLen := prefixLen + suffixLen
	if totalLen > maxLength || (totalLen == maxLength && suffix[0:1] == shortenedPrefix) {
		// Either it's just too long, or it's exactly the right length but it happens to
		// start with the character that we use to denote a shortened string, which could
		// result in a clash.  Hash the value and truncate...
		hasher := sha256.New()
		_, err := hasher.Write([]byte(suffix))
		if err != nil {
			log.WithError(err).Panic("Failed to write suffix to hash.")
		}
		hash := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
		charsLeftForHash := maxLength - 1 - prefixLen
		if charsLeftForHash <= 0 {
			log.Panicf("GetLengthLimitedID: maxLength %d is too small for prefix %q (length %d); "+
				"need at least %d", maxLength, fixedPrefix, prefixLen, prefixLen+2)
		}
		return fixedPrefix + shortenedPrefix + hash[0:charsLeftForHash]
	}
	// No need to shorten.
	return fixedPrefix + suffix
}
