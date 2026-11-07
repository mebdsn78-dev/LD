# LayerGuard

<p align="center"><img src="LayerGuard/src/layerguard_1024.png" width="128" alt="LayerGuard icon"></p>

**A layered application-sandbox manager for Windows (C/C++, Win32).**
Runs programs inside 16 privilege tiers (0–15), starting everything unknown in a locked-down sandbox and letting *you* decide, with a password on a protected desktop, when a program deserves more.

[العربية ↓](#العربية)

> ⚠️ **Experimental.** LayerGuard is a research/learning project. It has **not** been security-audited and must not be your only line of defense. Read [Limits](#limits) before relying on it.

## Features

- **16 layers.** Layer 0 is a shared, locked-down sandbox (AppContainer + Job Object). Higher layers progressively widen what an app may do. Layer 15 (kernel/root) is reserved and can never be assigned to an app.
- **Manual elevation.** Right-click an app → *Change Layer* → pick a layer → enter your password. Lowering a layer needs no password. Each raise is limited to 4 layers at a time.
- **Secure password prompt.** Third-party processes are frozen, then the prompt appears on a separate private desktop, showing a personal anti-phishing phrase. A watchdog thaws everything automatically if anything hangs.
- **Real-time signature check.** Every app is verified (Authenticode + Windows catalogs) when added, at every launch, and every 10 s. Genuine Windows components start in the clean layer 12; everything else starts in layer 0. An app whose signature gets *worse* is demoted to layer 0 automatically.
- **Live process monitor.** New processes are listed with their signature status; unsigned/invalid ones can be offered a re-run inside layer 0.
- **USB keyboard guard.** A newly attached keyboard is disabled at once and you are asked *“Is this really a keyboard you plugged in?”* before it is enabled.
- **Tamper-evident audit log.** Append-only, each line carries the SHA-256 of the previous one; one click verifies the whole chain.

## Build

Requirements: Windows 10/11, Visual Studio 2022 (or Build Tools) with **Desktop development with C++** and a Windows SDK, CMake ≥ 3.20, Ninja.

Open **x64 Native Tools Command Prompt for VS 2022**, then:

```bat
cd LayerGuard
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
build\LayerGuard.exe
```

The program asks for Administrator rights (it creates Job Objects and disables devices). Data is stored in `%ProgramData%\LayerGuard\`.
A pre-built `.exe` is **not** a substitute for building it yourself: only run binaries you built or can verify (see [SECURITY.md](SECURITY.md)).

## Limits

- Windows has only four integrity levels; layers 4–14 differ by token and Job Object limits, not by 16 real kernel levels. Layers 12–14 currently differ only in resource limits.
- The password prompt is a private desktop, which is **weaker than the UAC secure desktop**; a SYSTEM/Administrator process can reach it. Process freezing does **not** stop kernel-mode, driver, hypervisor or hardware keyloggers.
- The live monitor **detects after start**; it cannot block execution (that needs a kernel driver or WDAC/AppLocker). Very short-lived processes can be missed.
- The USB guard acts *after* Windows enumerates the device, so a very fast HID attack device may type a few keystrokes first. Combine it with Group Policy *Device Installation Restrictions*.
- AppContainer (layers 0–3) can only run programs whose files are readable by “ALL APPLICATION PACKAGES”; programs in user folders often fail with *Access denied*.

More detail: [LayerGuard/README.md](LayerGuard/README.md).

## Contributing

Everyone is welcome: bug reports, ideas, docs, tests, code. See [CONTRIBUTING.md](CONTRIBUTING.md). Security problems: please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

[MIT](LICENSE) — free for anyone to use, modify and share, including commercially.

---

## العربية

**LayerGuard** مدير عزل للتطبيقات على Windows مكتوب بـ C/C++. يشغّل البرامج داخل **16 طبقة صلاحيات (0–15)**: كل برنامج مجهول يبدأ في صندوق معزول، وأنت من يقرر رفعه بكلمة مرور على سطح مكتب محمي.

**المميزات:** 16 طبقة، رفع الطبقة بالزر الأيمن وكلمة المرور، جلسة إدخال آمنة مع تجميد عمليات الطرف الثالث وعبارة تحقق ضد الانتحال، فحص التوقيع الرقمي لحظياً (برامج Windows الأصلية تبدأ في الطبقة 12 والبقية في 0)، مراقب فوري للعمليات الجديدة، حارس لوحة مفاتيح USB، وسجل تدقيق مقاوم للتلاعب.

> ⚠️ **تجريبي.** لم تُجرَ عليه مراجعة أمنية، ولا يصلح أن يكون خط دفاعك الوحيد. اقرأ قسم *Limits* أعلاه.

**البناء:** افتح *x64 Native Tools Command Prompt for VS 2022* ثم نفّذ:
```bat
cd LayerGuard
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

**المساهمة:** الجميع مدعو: بلاغات أخطاء، أفكار، توثيق، اختبارات، شيفرة. انظر [CONTRIBUTING.md](CONTRIBUTING.md). **الترخيص:** MIT، مجاني للجميع للاستخدام والتعديل والمشاركة حتى تجارياً.
