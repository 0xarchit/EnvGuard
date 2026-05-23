# Security Policy

## Supported Versions

As EnvGuard is in early active development, there are currently no stable releases. Security fixes are applied directly to the primary branch.

| Version | Supported |
| :--- | :--- |
| Main Branch | :white_check_mark: Yes |
| < v0.1.0 | :x: No |

We strongly recommend that developers only use the latest commit from the `main` branch for testing purposes, as previous commits will not receive backported security updates.

---

## Reporting a Vulnerability

**DO NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability or potential weakness in EnvGuard, please report it privately through GitHub's Private Security Advisory system:
* [Draft a new Security Advisory](https://github.com/0xarchit/EnvGuard/security/advisories/new)

If you are unable to use the advisory system, please contact the maintainer directly via the contact methods specified on their profile page.

### What to Include in a Vulnerability Report
To help us triage and resolve the issue quickly, please include the following details in your private report:
1. **Description:** A detailed explanation of the vulnerability and its potential impact.
2. **Affected Component:** Specify the package or module involved (e.g. cryptography, session PTY spawning, storage, zeroization).
3. **Reproduction Steps:** A step-by-step guide or a minimal proof of concept (PoC) to reproduce the vulnerability.
4. **Suggested Mitigation:** A proposed fix or mitigation strategy if you have one.

---

## Our Response Commitment

We treat every security report with the highest priority:
* **Acknowledgment:** We will acknowledge receipt of your report within 72 hours.
* **Triage & Assessment:** We will perform a preliminary triage and communicate our assessment/severity rating within 7 days.
* **Fix & Release:** We will work to resolve the issue as quickly as possible and coordinate a public release containing the security patch, alongside appropriate attribution for your discovery.

---

## Threat Model

EnvGuard is designed to secure developer credentials and environment runtimes. We assume that:
* The host operating system's kernel is untrusted by default unless proper boundary isolation is used.
* Memory scraping is a realistic threat; therefore, all sensitive credentials must reside in zeroed memory spaces.
* Development environments are high-value targets. 

Any bug that facilitates unauthorized credential access, unencrypted disk leaks, memory retention of secrets, or privilege escalation is classified as a critical security vulnerability and handled with extreme urgency.
