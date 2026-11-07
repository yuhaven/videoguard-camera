# VideoSercet — Tamper-Proof Video (Algorithm + CLI + Mobile App)

[![build-apk](https://github.com/yuhaven/videoguard-camera/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/yuhaven/videoguard-camera/actions/workflows/build.yml)
[中文](README.md) | English

Once a video is processed by this algorithm, **any** change — watermarking, color grading, occlusion, insertion, splicing, audio-track replacement, re-encoding, or wholesale substitution — is fully detectable, down to a single flipped byte.

## The 3-Step Algorithm (SimpleGuard)

```
① H = SHA-256(all bytes of the video file)   —— hash the whole file once
② S = Ed25519 private-key signature of H      —— asymmetric signature
③ Verify: recompute H', H'==H and public-key verification pass → intact; otherwise → tampered
```

**Why any change is always detected**: SHA-256 is collision-resistant (one flipped byte ⇒ different hash), and an Ed25519 signature cannot be forged without the private key. Every kind of edit ultimately changes bytes, so everything is caught.

## Contents

| Form | Location | Description |
|---|---|---|
| **Mobile app (Android APK)** | [apps/camera_guard](apps/camera_guard) | Tamper-proof camera: auto hash + sign + package into `.sgd` right after capture; streaming for huge videos; verify / share / export public key |
| App design doc | [docs/APP设计.md](docs/APP设计.md) | Features, architecture, large-video strategy, build & usage (Chinese) |
| Algorithm design | [docs/简单方案.md](docs/简单方案.md) | One-page algorithm design (Chinese) |
| Dart core package | [packages/simple_guard_dart](packages/simple_guard_dart) | Streaming SHA-256, Ed25519, `.sgd` I/O; 13 unit tests green |
| Python CLI | [src/simple_guard.py](src/simple_guard.py) | Byte-level interoperable with the app and Dart package |
| Demo & results | [demo/run_demo_simple.py](demo/run_demo_simple.py) → [report.md](demo/out_simple/report.md) | 10 attack classes all detected |
| Advanced scheme (optional) | [docs/算法设计.md](docs/算法设计.md) | Layered detection: distinguishes "re-encoded but visually unchanged", localizes tampering to the second |

## Mobile App Quick Start

**Prebuilt APK: download from [GitHub Releases](https://github.com/yuhaven/videoguard-camera/releases) (v1.0.0, `app-release.apk`, release-signed, minSdk 24 = Android 7.0+).**

```powershell
# One-shot toolchain setup (JDK17 + Android SDK + Flutter)
powershell -ExecutionPolicy Bypass -File tools\setup_android.ps1
# One-shot build (analyze + test + release APK)
powershell -ExecutionPolicy Bypass -File tools\build_apk.ps1
# Output: apps\camera_guard\build\app\outputs\flutter-apk\app-release.apk
adb install app-release.apk
```

Usage: open the app → record/take a photo (a signing key pair is generated on first launch; the private key stays in the device secure storage and is never exportable) → auto signing → result page shows hash & signature → share the `.sgd` → anyone can verify it in the app or with the CLI.

## CLI Quick Start

```powershell
python src\simple_guard.py genkey --dir demo\out_simple
python src\simple_guard.py sign demo\out_simple\sample.mp4 demo\out_simple\sample.sgd --privkey demo\out_simple\identity.key
python src\simple_guard.py verify demo\out_simple\sample.sgd --pubkey demo\out_simple\identity.pub   # 0=intact 1=tampered
python src\simple_guard.py check demo\out_simple\watermark.mp4 --sigfile demo\out_simple\sample.sgd
```

## Verified Results

- 10 attack classes (1-byte flip / watermark / color / occlusion / insertion / splice / audio swap / substitution / container tamper / "smart attack" that updates the hash without the signing key) — all detected: [demo/out_simple/report.md](demo/out_simple/report.md)
- Dart core package: 13/13 unit tests (RFC 8032 vector, streaming, incremental, bidirectional interop with the Python CLI)
- Large-file benchmark: 2 GB streamed hashing, 173 MiB/s on desktop JIT, O(1) memory; in the app, hashing runs in a background isolate with a progress bar

## Test & Build Status

```powershell
cd packages\simple_guard_dart; dart test              # 13/13
cd apps\camera_guard; flutter analyze; flutter test    # 7/7
```

CI (GitHub Actions) builds the release APK on every push to `main`.

## License

MIT — see [LICENSE](LICENSE). The committed keystore is a demo signing key; replace it with your own for real releases.
