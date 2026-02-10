# TLS Configuration Guide

## Overview

The Calico API server supports comprehensive TLS configuration through environment variables, allowing fine-grained control over security settings for production environments.

## Environment Variables

### TLS_MIN_VERSION

Controls the minimum TLS protocol version accepted by the API server.

**Supported Values:**
- `""` (empty string) or `"1.2"` - TLS 1.2 minimum (default)
- `"1.3"` - TLS 1.3 minimum

**Default:** TLS 1.2

**Example:**
```bash
export TLS_MIN_VERSION=1.3
```

### TLS_CIPHER_SUITES

Specifies a comma-separated list of cipher suites to be used. If not set, a default set of strong ciphers is used.

**Example:**
```bash
export TLS_CIPHER_SUITES="TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384"
```

## Configuration Examples

### Example 1: TLS 1.3 Only with TLS 1.3 Ciphers

For maximum security, restrict to TLS 1.3 with strong ciphers:

```bash
export TLS_MIN_VERSION=1.3
export TLS_CIPHER_SUITES="TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256"
```

**Use Case:** High-security environments where all clients support TLS 1.3

### Example 2: TLS 1.2 with Strong Ciphers (Default)

Maintain backward compatibility while using strong ciphers:

```bash
export TLS_MIN_VERSION=1.2
export TLS_CIPHER_SUITES="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
```

**Use Case:** Environments with mixed client versions

### Example 3: Default Configuration

For most deployments, the defaults provide a good security/compatibility balance:

```bash
# No configuration needed - uses sensible defaults
# Defaults to TLS 1.2 minimum with a curated set of strong ciphers
```

## Compatibility Matrix

### TLS 1.2 Ciphers

| Cipher Suite | Min TLS Version | Security Level |
|-------------|-----------------|----------------|
| TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 | 1.2 | High |
| TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | 1.2 | High |
| TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 | 1.2 | High |
| TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | 1.2 | High |
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | 1.2 | High |
| TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | 1.2 | High |

### TLS 1.3 Ciphers

| Cipher Suite | Min TLS Version | Security Level |
|-------------|-----------------|----------------|
| TLS_AES_256_GCM_SHA384 | 1.3 | High |
| TLS_CHACHA20_POLY1305_SHA256 | 1.3 | High |
| TLS_AES_128_GCM_SHA256 | 1.3 | High |

## Important Configuration Rules

### Rule 1: Match TLS Version with Cipher Suites

When using TLS 1.3-only ciphers, you **must** set `TLS_MIN_VERSION=1.3`:

```bash
# ✅ CORRECT
export TLS_MIN_VERSION=1.3
export TLS_CIPHER_SUITES="TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384"

# ❌ INCORRECT - Will cause startup failure
export TLS_MIN_VERSION=1.2
export TLS_CIPHER_SUITES="TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384"
```

**Why?** Go's HTTP/2 server validates that at least one cipher is compatible with the minimum TLS version. TLS 1.3 ciphers are not valid for TLS 1.2.

### Rule 2: Mixing TLS 1.2 and 1.3 Ciphers

You can mix ciphers from both versions when using `TLS_MIN_VERSION=1.2`:

```bash
# ✅ CORRECT - Will negotiate TLS 1.3 with supporting clients
export TLS_MIN_VERSION=1.2
export TLS_CIPHER_SUITES="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_AES_128_GCM_SHA256"
```

## Troubleshooting

### Error: "API server fails to start"

**Symptom:** API server exits immediately after startup with HTTP/2 cipher validation error.

**Cause:** Mismatch between `TLS_MIN_VERSION` and configured cipher suites.

**Solution:**
1. Check your `TLS_CIPHER_SUITES` configuration
2. If using only TLS 1.3 ciphers, set `TLS_MIN_VERSION=1.3`
3. If using TLS 1.2 ciphers, ensure `TLS_MIN_VERSION=1.2` or leave unset

### Error: "Unsupported TLS version"

**Symptom:** Error message indicating invalid TLS_MIN_VERSION value.

**Cause:** Invalid value for `TLS_MIN_VERSION` environment variable.

**Solution:** Use only supported values: `1.2` or `1.3`

### Error: "Unsupported cipher"

**Symptom:** API server fails to start with error about unsupported cipher suite.

**Cause:** Invalid or unsupported cipher name in `TLS_CIPHER_SUITES`.

**Solution:** Verify cipher names against the compatibility matrix above. Use exact names as shown in Go's crypto/tls package.

## Security Best Practices

### 1. Use TLS 1.3 When Possible

TLS 1.3 provides improved security and performance:
- Faster handshakes
- Forward secrecy by default
- Removal of legacy cryptographic algorithms

### 2. Regularly Update Cipher Configurations

Stay current with security advisories and disable weak ciphers:
- Review NIST guidelines periodically
- Monitor CVE databases for cipher vulnerabilities
- Update configurations during maintenance windows

### 3. Test Configuration Changes

Before deploying to production:
1. Test in a staging environment
2. Verify client compatibility
3. Monitor connection success rates
4. Have a rollback plan

### 4. Enable TLS Logging

For debugging TLS issues:
```bash
export GODEBUG=tls13=1  # Enable TLS 1.3 debug logging
```

### 5. Client Certificate Authentication

For enhanced security, combine TLS configuration with mutual TLS (mTLS):
- Require client certificates
- Validate certificate chains
- Use short-lived certificates

## Verification

### Test TLS Configuration

Use `openssl` to test your TLS configuration:

```bash
# Test TLS 1.3 connection
openssl s_client -connect api-server:443 -tls1_3

# List negotiated cipher
openssl s_client -connect api-server:443 -showcerts | grep "Cipher"

# Test specific cipher suite
openssl s_client -connect api-server:443 -cipher TLS_AES_128_GCM_SHA256
```

### Monitor TLS Metrics

Monitor these metrics in production:
- TLS handshake duration
- TLS version distribution (1.2 vs 1.3)
- Cipher suite usage
- TLS error rates

## Default Cipher List

When `TLS_CIPHER_SUITES` is not set, the following ciphers are used by default:

**TLS 1.3 Ciphers:**
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256
- TLS_AES_128_GCM_SHA256

**TLS 1.2 Ciphers:**
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

These defaults provide a good balance of security and compatibility.

## Related Documentation

- [Calico Security Documentation](../SECURITY.md)
- [Kubernetes TLS Best Practices](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)

## References

- [RFC 8446 - TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [RFC 5246 - TLS 1.2](https://datatracker.ietf.org/doc/html/rfc5246)
- [Go crypto/tls Package](https://pkg.go.dev/crypto/tls)
