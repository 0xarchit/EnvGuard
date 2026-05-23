# EnvGuard

### Modern, Native, Cross-Platform Developer Secrets and Environment Runtime Manager

EnvGuard is a secure local runtime-based credential system that completely replaces traditional plaintext `.env` files. Developers manage secrets through a native desktop application that organizes environment variables into isolated project profiles. Credentials are injected into spawned terminal or process sessions dynamically and exist solely within memory—once your session ends, the secrets vanish.

---

## Why EnvGuard? The Problem with `.env` Files

For years, developers have relied on `.env` files to store configuration and sensitive keys. This approach introduces significant security liabilities:

1. **Plaintext Storage:** Secrets sit unencrypted on local disks, accessible by any process running on the system or unauthorized users with physical access.
2. **Accidental Commits:** Despite `.gitignore` rules, `.env` files are routinely pushed to public repositories, resulting in immediate compromise of critical keys.
3. **Lack of Lifecycle Control:** Environment variables persist in shells indefinitely until closed, leaking across processes or remaining accessible in background contexts.
4. **Weak Access Audits:** There is no centralized tracking or security auditing of who, when, or what process requested access to a specific credential.

EnvGuard shifts the paradigm. Environment variables should behave like temporary, authenticated runtime sessions rather than permanent plaintext files.

---

## Key Feature Concepts

### isolated Project Profiles
Manage separate configurations for development, staging, testing, and production. Profiles are cryptographically isolated from one another.

### On-Demand Session Injection
Instead of storing variables in disk files, EnvGuard spawns child processes (terminal or command runners) and injects environment variables directly into their memory space. Sub-processes inherit these variables, but parent or parallel sessions remain completely blind to them.

### Memory Zeroization
Security-sensitive keys and passwords are actively zeroed out from system memory immediately after use, preventing memory-scraping attacks on the developer machine.

### Expiration Timers
Define automated session lifetimes. Secrets automatically expire and disappear from the active runtime after the specified duration, minimizing the window of vulnerability.

---

## Platform Support Matrix

EnvGuard produces independent static binaries for each target platform with no external runtime dependencies:

| Operating System | Distributions/Versions | Packaging Targets |
| :--- | :--- | :--- |
| **Windows** | Windows 10, Windows 11 | MSI, Winget |
| **macOS** | Apple Silicon (M1/M2/M3), Intel | DMG, Homebrew |
| **Linux** | Arch Linux, Ubuntu, Debian, Fedora | AppImage, AUR (pkgbuild), DEB, RPM |

---

## Tech Stack & Architecture Choices

EnvGuard is built entirely in Rust, avoiding heavy frameworks like Electron or Chromium to ensure optimal performance and security.

* **Rust Core:** Provides memory safety, high performance, and allows compiling to standalone static binaries with no external runtime dependencies.
* **Slint UI:** A lightweight, modern, GPU-accelerated native user interface toolkit that consumes minimal memory compared to webviews.
* **Tokio:** An asynchronous runtime for handling non-blocking system tasks, timers, and PTY processes efficiently.
* **AES-256-GCM:** Authenticated symmetric encryption used to protect local secrets databases.
* **Argon2id:** State-of-the-art key derivation function to derive secure database keys from your master password.
* **SQLCipher:** Encrypted SQLite engine used to store project configurations, profile data, and encrypted secrets locally.
* **Zeroize Crate:** Provides secure memory clearing by zeroizing Rust data structures containing cryptographic materials or sensitive credentials.

---

## Getting Started

EnvGuard is currently in active early development. Stable, ready-to-install releases are not yet available. 

To track progress and get updates when the first pre-release builds become available:
1. Keep an eye on our [Releases](https://github.com/0xarchit/EnvGuard/releases) page for downloadable installer packages (MSI, DMG, AppImage).
2. Read the [CONTRIBUTING.md](.github/CONTRIBUTING.md) guide if you are interested in local development, compiling the codebase, or reviewing the early-stage code.

---

## Roadmap

### Phase 1: Core Cryptography & Storage
* AES-GCM encrypted local SQLite storage using SQLCipher.
* Argon2id master password derivation with customizable memory costs.
* Zeroize integration for cryptographic material and secret values.
* Local secret import scanning for existing `.env` files.

### Phase 2: Runtime Injection & UI
* Slint desktop application implementation (GPU-accelerated UI).
* Local PTY-based shell spawning and terminal injection.
* Automated session expiration timers and lifecycle controls.
* Native OS keychain integrations (Windows Credential Manager, macOS Keychain, Linux Secret Service).

### Phase 3: Developer Utilities & Integrations
* Git leak pre-commit hooks to detect unencrypted credentials.
* SSH key orchestration and dynamic injection.
* Docker runtime credential passing.
* Dynamic cloud token integration (AWS, GCP, Vault).
* Secure, end-to-end encrypted team credential sharing.

---

## Contributing

We welcome contributions from the developer and security communities. Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) to understand our development workflow, branch structures, code requirements, and security guidelines before submitting a Pull Request.

---

## License

EnvGuard is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for the full text.
