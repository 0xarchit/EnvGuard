# Contributing to EnvGuard

Thank you for your interest in contributing to EnvGuard! We welcome contributions from developers and security researchers. As a native, security-focused credentials manager built in Rust, we maintain high standards of code hygiene, security, and repository structure.

Please review this guide fully before opening an issue or pull request.

---

## How to Contribute

### 1. Reporting Bugs
If you find a bug, please use the **Bug Report** template under GitHub issues. Be sure to fill out all the fields, including:
* Clear description and steps to reproduce.
* Expected vs. actual behavior.
* Target platform details (OS name, version, and architecture).
* Logs or error output, making absolutely certain to redact any sensitive API keys, passwords, or credentials before submitting.

### 2. Proposing Features
For new ideas or features, use the **Feature Request** template. Because EnvGuard handles highly sensitive user data, you must complete the mandatory "Security & Privacy Implications" section. We evaluate all features through a security-first threat model.

### 3. General Tasks & Questions
For tasks, documentation suggestions, or general questions, use the standard **Issue** template and select the appropriate codebase zone (crypto, storage, session, UI, build/CI, docs).

---

## Branch and Pull Request Workflow

We follow a structured issue-first development workflow:

1. **Link to an Issue:** Every Pull Request (PR) must address an existing, approved GitHub issue. If no issue exists, please open one first and wait for maintainer alignment.
2. **Branch Naming:** Create a dedicated branch for each issue from the `main` branch. Use the naming convention `issue-<number>-<description>` (e.g., `issue-42-aes-gcm-zeroize`).
3. **Draft PRs:** Feel free to open a Draft PR early to receive architecture feedback.
4. **Referencing Issues:** Use standard GitHub closing keywords in your PR description (e.g., `Closes #123`) to ensure issues are automatically closed when your PR is merged.
5. **No Force Pushes:** Avoid force-pushing to shared branches. Rebase on `main` when necessary.

---

## Code Quality and Development Philosophy

We maintain extremely strict code standards to ensure EnvGuard is robust, secure, and clean:

### Complete Implementations Only
We do not accept partial code submissions, skeleton implementations, or placeholders. All submitted code must be production-ready, fully functional, and compile without warnings.

### Strict Zero-Comments Rule
To maintain absolute codebase clarity, we do not allow comments of any kind in the source files. 
* Do not include inline, full line, block, paragraph, or documentation-inhibiting comments in any file.
* This means **no** `//`, `/* */`, `///` or other comment syntax inside your code.
* Instead of comments, write expressive self-documenting code with clear variable and function names.
* Use native Rust public item docstrings on modules, structs, and functions if documentation is needed, but keep actual code bodies completely clean of comments.

### No Temporary Constructs
Ensure that no `.unwrap()`, `panic!()`, or `todo!()` macros remain in production code path implementations. Errors must be modeled explicitly and handled gracefully via Rust's standard `Result` propagation.

---

## Security-Sensitive Coding Rules

Because EnvGuard is a security tool responsible for developer credentials, safety is paramount:

1. **Memory Safety & Zeroization:** All sensitive data structures (passwords, tokens, decrypted variables) must implement or utilize the `zeroize` crate to ensure memory is securely wiped as soon as it goes out of scope.
2. **No Unsafe Code:** Avoid `unsafe` blocks. If an external library demands `unsafe`, it must be thoroughly vetted and approved by the maintainers.
3. **No Logging of Secrets:** Never write credentials or sensitive variables to stdout, stderr, or external log files. All log statements must be audited to prevent inadvertent data leakage.
4. **Static Binary Compilation:** Keep dependencies lightweight. Our target is a fully independent static binary with no external runtime dependencies (e.g., no Node.js, Electron, or webview dependencies).

---

## Development Environment Setup

Setting up EnvGuard locally is straightforward:

1. Install the latest stable Rust toolchain using [rustup](https://rustup.rs/).
2. Clone the repository and navigate into the project directory:
   ```bash
   git clone https://github.com/0xarchit/EnvGuard.git
   cd EnvGuard
   ```
3. Compile the project:
   ```bash
   cargo build
   ```
4. Run the test suite to ensure everything is functional:
   ```bash
   cargo test
   ```

Before submitting your PR, ensure that:
* `cargo fmt` is run to format the codebase.
* `cargo clippy` passes cleanly with no warnings.
