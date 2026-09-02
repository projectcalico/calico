// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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

package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

var chars = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
var charLen = big.NewInt(int64(len(chars)))

func GeneratePassword(length int) string {
	var b strings.Builder
	for b.Len() < length {
		idx, err := rand.Int(rand.Reader, charLen)
		if err != nil {
			panic(fmt.Errorf("failed to read crypto/rand data: %w", err))
		}
		b.WriteRune(chars[idx.Int64()])
	}
	return b.String()
}
