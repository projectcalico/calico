# TLS Configuration Guide

## Quick Reference

Configure TLS security via environment variables:

| Variable | Values | Default | Purpose |
|----------|--------|---------|---------|
| `TLS_MIN_VERSION` | `1.2`, `1.3` | `1.2` | Minimum TLS protocol version |
| `TLS_CIPHER_SUITES` | Cipher list (comma-separated) | Strong defaults | Allowed cipher suites |

## Configuration Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    TLS Configuration                     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  TLS_MIN_VERSION ─────┐                                 │
│                       ├──► Validation ──► API Server    │
│  TLS_CIPHER_SUITES ───┘                                 │
│                                                          │
│  ┌──────────────┐      ┌──────────────┐                │
│  │  TLS 1.2     │◄─────┤  TLS 1.2     │                │
│  │  Ciphers     │      │  Ciphers OK  │                │
│  └──────────────┘      └──────────────┘                │
│                                                          │
│  ┌──────────────┐      ┌──────────────┐                │
│  │  TLS 1.3     │  ✗───┤  TLS 1.2     │ ← FAILS        │
│  │  Ciphers     │      │  Min Version │                │
│  └──────────────┘      └──────────────┘                │
│                                                          │
│  ┌──────────────┐      ┌──────────────┐                │
│  │  TLS 1.3     │◄─────┤  TLS 1.3     │                │
│  │  Ciphers     │      │  Min Version │                │
│  └──────────────┘      └──────────────┘                │
└─────────────────────────────────────────────────────────┘
```

## Valid Configuration Matrix

| TLS_MIN_VERSION | TLS 1.2 Ciphers | TLS 1.3 Ciphers | Mixed | Result |
|-----------------|-----------------|-----------------|-------|--------|
| `1.2` (default) | ✅ | ✅ | ✅ | **Works** - Negotiates best available |
| `1.3` | ❌ | ✅ | ❌ | **Works** - TLS 1.3 only |
| `1.2` | ✅ | ❌ | ❌ | **Works** - TLS 1.2 compatible |
| `1.2` | ❌ | ✅ (only) | ❌ | **FAILS** - No TLS 1.2 ciphers |

## Configuration Examples

### 🔒 Maximum Security (TLS 1.3 Only)
```bash
export TLS_MIN_VERSION=1.3
export TLS_CIPHER_SUITES="TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256"
```
**Result:** Only TLS 1.3 clients can connect with specified ciphers

### 🔓 Backward Compatible (Default)
```bash
export TLS_MIN_VERSION=1.2
export TLS_CIPHER_SUITES="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_AES_128_GCM_SHA256"
```
**Result:** TLS 1.2+ clients supported, TLS 1.3 preferred when available

### ⚙️ Default (No Configuration)
```bash
# Use built-in defaults
```
**Result:** TLS 1.2+ with curated strong ciphers (both 1.2 and 1.3)

## Cipher Suite Reference

```
TLS 1.2 Ciphers              TLS 1.3 Ciphers
─────────────────            ──────────────────
ECDHE_*_AES_256_GCM    ──┐   TLS_AES_256_GCM
ECDHE_*_AES_128_GCM    ──┤   TLS_AES_128_GCM
ECDHE_*_CHACHA20       ──┘   TLS_CHACHA20_POLY1305
                             
Min Version: TLS 1.2         Min Version: TLS 1.3
Compatible: Wide             Compatible: Modern clients
Security: High               Security: Highest
```

## Common Issue: Startup Failure

**Symptom:** API server fails with HTTP/2 cipher validation error

**Cause & Solution:**

| Configuration | Problem | Fix |
|--------------|---------|-----|
| TLS 1.3 ciphers + `TLS_MIN_VERSION=1.2` | ❌ Version mismatch | Set `TLS_MIN_VERSION=1.3` |
| Invalid cipher name | ❌ Unknown cipher | Use exact names from tables |
| Empty cipher list | ❌ No ciphers | Remove `TLS_CIPHER_SUITES` for defaults |

**Debug:**
```bash
# Check configuration
echo "Min Version: $TLS_MIN_VERSION"
echo "Ciphers: $TLS_CIPHER_SUITES"

# Test connection
openssl s_client -connect api-server:443 -tls1_3
```

## Supported Ciphers

### TLS 1.2 Ciphers (Compatible)
```
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384  
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
```

### TLS 1.3 Ciphers (Modern)
```
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256
```

## Security Recommendations

| Priority | Recommendation | Configuration |
|----------|---------------|---------------|
| 🔴 High Security | TLS 1.3 only | `TLS_MIN_VERSION=1.3` with TLS 1.3 ciphers |
| 🟡 Balanced | Default settings | No configuration needed |
| 🟢 Compatible | TLS 1.2+ mixed | `TLS_MIN_VERSION=1.2` with both cipher types |

## Testing Your Configuration

```bash
# Test TLS 1.3 support
openssl s_client -connect api-server:443 -tls1_3

# Show negotiated cipher
openssl s_client -connect api-server:443 -showcerts 2>/dev/null | grep "Cipher"

# Verify specific cipher
openssl s_client -connect api-server:443 -cipher TLS_AES_128_GCM_SHA256
```

## Key Takeaway

```
┌────────────────────────────────────────────────────────┐
│  Rule: Match cipher suites to minimum TLS version     │
│                                                        │
│  TLS 1.3 ciphers → Requires TLS_MIN_VERSION=1.3      │
│  TLS 1.2 ciphers → Works with any min version         │
│  Mixed ciphers   → Use TLS_MIN_VERSION=1.2 (default)  │
└────────────────────────────────────────────────────────┘
```

**Fixes Issue #11706** - Resolves startup failures when configuring TLS 1.3-only cipher suites.
