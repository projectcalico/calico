# Security Policy

## Supported Versions

The Tigera team generally support the most recent two minor versions
of Project Calico on a rolling basis.  Support for older versions is on a 
case-by-case basis.  For example, at the time of writing, 
Calico v3.26.x and v3.25.x are supported.  When v3.27.0 is released,
automatic support for v3.25.x is dropped.

## Reporting a Vulnerability

Please follow responsible disclosure best practices and [Tigera's Vulnerability Disclosure Policy](https://www.tigera.io/vulnerability-disclosure/) when submitting
security vulnerabilities.  **Do not** create a GitHub issue or pull 
request because those are immediately public. Instead:

*  Email [psirt@projectcalico.org](psirt@projectcalico.org).
*  Report a private [security advisory](https://github.com/projectcalico/calico/security/advisories)
  through the GitHub interface.

Please include as much information as possible, including the
affected version(s) and steps to reproduce.

## Third Party Vulnerabilities

When using automated security scanning tools (e.g., Trivy, Grype, Docker Scout), CVEs may be flagged in Calico container images due to vulnerabilities in third-party dependencies. Before submitting any reports related to these findings, check the [Tigera VEX repository](https://github.com/tigera/vex).
The repository provides analysis of third-party CVEs that may appear in Calico images, including whether they are exploitable or applicable to our supported versions. Reviewing this information helps avoid duplicate reports and offers context for scanner-detected issues.