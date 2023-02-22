//go:build !boringcrypto

package tls

// BuiltWithBoringCrypto if true, strict fips mode is enforced.
const BuiltWithBoringCrypto = false
