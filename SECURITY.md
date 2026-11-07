# Security Policy

LayerGuard is an experimental security tool. It has not been independently audited. Treat it as a defense-in-depth layer, never as the only protection.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository.
Include: what you found, the affected file/function, how to reproduce it, and the impact you expect.

You should get an answer within about 7 days. Please allow reasonable time for a fix before disclosing publicly. / يرجى عدم نشر الثغرة علناً قبل إتاحة وقت معقول للإصلاح.

## What is in scope

- Bypassing the layer policy or the password check (raising an app without authentication).
- Escaping a sandbox layer (AppContainer / Job Object / token restrictions).
- Forging, truncating or silently editing the audit log without breaking the hash chain.
- Reading or leaking the password, or defeating the secure prompt.
- Making the USB guard approve a device without the user's answer.
- Any way to leave the desktop permanently frozen (denial of service).

Known limits (kernel-mode keyloggers, detection-after-start, weaker-than-UAC secure desktop, etc.) are listed in the README and are not vulnerabilities by themselves.

## Verifying binaries

Prefer building from source. If a release binary is published, it must come with its SHA-256 hash in the release notes; never run an `.exe` of this tool from an unknown source. The tool is designed to flag unsigned programs, and itself is unsigned unless a release says otherwise.
