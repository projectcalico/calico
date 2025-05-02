# Security Policy

## Supported Versions

The Tigera team generally support the most recent two minor versions
of Project Calico on a rolling basis.  Support for older versions is on a 
case-by-case basis.  For example, at the time of writing, 
Calico v3.26.x and v3.25.x are supported.  When v3.27.0 is released,
automatic support for v3.25.x is dropped.

## CVEs Detected by Security Scanners

If you are using automated tools (e.g., Trivy, Grype, Docker Scout, etc.) and find CVEs in Calico container images or dependencies, please check our [VEX repository](https://github.com/tigera/vex) **before submitting** a report. This repository contains Tigera’s analysis of known CVEs, including whether they are exploitable or applicable to our supported versions. This helps reduce duplicate reports and gives you context on known scanner findings.

## Reporting a Vulnerability

Please follow responsible disclosure best practices and [Tigera's Vulnerability Disclosure Policy](https://www.tigera.io/vulnerability-disclosure/) when submitting
security vulnerabilities.  **Do not** create a GitHub issue or pull 
request because those are immediately public. Instead:

*  Email [psirt@projectcalico.org](psirt@projectcalico.org).
*  Report a private [security advisory](https://github.com/projectcalico/calico/security/advisories)
  through the GitHub interface.

Please include as much information as possible, including the
affected version(s) and steps to reproduce.
