# Security Policy

## Supported Versions

The Tigera team generally support the most recent two minor versions
of Project Calico on a rolling basis.  Support for older versions is on a 
case-by-case basis.  For example, at the time of writing, 
Calico v3.26.x and v3.25.x are supported.  When v3.27.0 is released,
automatic support for v3.25.x is dropped.

## Reporting a Vulnerability

Please follow responsible disclosure best practices when submitting
security vulnerabilities.  **Do not** create a Github issue or pull 
request because those are immediately public.  Instead, either:

* Email sirt@tigera.io.
* Create a private [security advisory](https://github.com/projectcalico/calico/security/advisories)
  through the Github interface.

Please include as much information as possible, including the
affected version(s) and steps to reproduce.

## Dependencies CVE policy

For releases of supported minor versions, the Calico team aim to ship
with no "High" level CVEs in libraries at the point of release.

For any ad hoc releases of earlier minor versions, this is done
on a best-effort basis.  (It is often impossible to update some
dependencies such as the Go compiler, or the Kubernetes API client 
library, due to external compatibility requirements.)
