//go:build boringcrypto
// +build boringcrypto

package tls

import (
	_ "crypto/tls/fipsonly"
)

// BuiltWithBoringCrypto if true, strict fips mode is enforced.
const BuiltWithBoringCrypto = true
