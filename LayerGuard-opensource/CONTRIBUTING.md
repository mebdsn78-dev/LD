# Contributing to LayerGuard

Thank you for helping. Anyone can contribute, no matter their experience. / المساهمة مفتوحة للجميع.

## Ways to help

- **Report a bug** or an unexpected *Access denied* (include the exact error and the layer).
- **Suggest an idea** (open an issue first for anything big).
- **Improve the docs**, translations (Arabic/English are the base), or the icon/UI.
- **Write code or tests.**

Good first areas: per-layer privilege differences for layers 12–14, an `IExplorerCommand` shell extension, granting AppContainer read access to a program's folder (with user consent), WDAC/AppLocker integration, a Windows-service split between UI and manager.

## Workflow

1. Fork the repo and create a branch: `git checkout -b my-change`.
2. Build it (see the README). Windows code can only be tested on Windows; say how you tested.
3. Keep the pure policy logic in `src/layers.c` testable without Windows: run `LayerGuard/tests/layers_test.c` (the CI does this on Linux).
4. Open a pull request describing **what** changed and **why**.

## Code guidelines

- C11 / C++17, Win32 API only, no third-party dependencies unless discussed first.
- Security-sensitive code (authentication, token/Job setup, the audit log, device handling) needs extra care: check every return value, never log passwords, wipe secrets with `SecureZeroMemory`, fail closed (deny on error).
- Every security decision must be written to the audit log.
- Don't weaken a default (e.g. don't auto-raise an app above layer 0 without authentication) without opening a discussion.
- Match the surrounding style; comment *why*, not *what*.

## Security issues

Do **not** open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License of contributions

By submitting a contribution you agree it is licensed under the project's [MIT license](LICENSE).

See also the [Code of Conduct](CODE_OF_CONDUCT.md).
