module fixture


go 1.23

// Versions pinned to match what gateway/coraza-wasm consumes (Coraza WAF):
// - go-re2 v1.6.0 is the last release that ships a TinyGo-targeted prebuilt
//   wasm static archive (libcre2 baked into internal/wasm/). v1.8.0+ removed
//   the TinyGo path entirely because libre2 now requires Abseil with thread
//   support, which TinyGo's libc++ shim does not provide.
// - go-libinjection v0.5.0 is the latest stable; ships a libinjection wasm
//   static archive that links cleanly against TinyGo's wasi-libc.
require (
	github.com/wasilibs/go-libinjection v0.5.0
	github.com/wasilibs/go-re2 v1.6.0
)

require (
	github.com/corazawaf/libinjection-go v0.1.2 // indirect
	github.com/magefile/mage v1.15.1-0.20230912152418-9f54e0f83e2a // indirect
	github.com/tetratelabs/wazero v1.7.2 // indirect
	golang.org/x/sys v0.21.0 // indirect
)
