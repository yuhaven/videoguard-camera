# VideoSercet — 加密视频防篡改（算法 + CLI + 手机 App）

视频经算法处理后，任何**加水印、改色彩、遮挡、插入、拼接、替换音轨、重编码、掉包**——只要视频文件出现一点改动，都能被完全验证出来。

## 三步算法（SimpleGuard）

```
① H = SHA-256(视频文件全部字节)      —— 对整个文件求一次哈希
② S = Ed25519 私钥签名(H)            —— 非对称签名（私钥签、公钥验）
③ 验证: 重算 H'，H'==H 且公钥验签通过 → 完全一致；否则 → 检出改动
```

**保证**：SHA-256 抗碰撞（改 1 字节哈希必变）+ Ed25519 无私钥无法伪造 → 一切修改最终都是字节变化，全部被检出。

## 交付物

| 形态 | 位置 | 说明 |
|---|---|---|
| **手机 App（Android APK）** | [apps/camera_guard](apps/camera_guard) | 防篡改相机：拍摄完成自动哈希+签名+打包 `.sgd`；超大视频流式处理；验证/分享/公钥导出 |
| App 设计文档 | [docs/APP设计.md](docs/APP设计.md) | 功能、架构、超大视频方案、构建与使用 |
| 算法设计（一页纸） | [docs/简单方案.md](docs/简单方案.md) | 极简算法、原理保证、攻击矩阵 |
| Dart 核心算法包 | [packages/simple_guard_dart](packages/simple_guard_dart) | 流式哈希、Ed25519、`.sgd` 读写；13 项单测全绿 |
| Python CLI | [src/simple_guard.py](src/simple_guard.py) | 与 App/Dart 包字节级互通 |
| 演示与实测 | [demo/run_demo_simple.py](demo/run_demo_simple.py) → [report.md](demo/out_simple/report.md) | 10 类攻击全部检出 |
| 进阶方案（可选） | [docs/算法设计.md](docs/算法设计.md) | 多层检测：能区分"重编码但画面没变"、定位篡改到秒 |

## 手机 App 快速上手

**安装包下载：本仓库的 GitHub Releases（v1.0.0，`app-release.apk`，50.2 MB，release 签名，minSdk 24 = Android 7.0+）。**

```powershell
# 一键准备工具链（JDK17 + Android SDK + Flutter）
powershell -ExecutionPolicy Bypass -File tools\setup_android.ps1
# 一键构建（analyze + test + release APK）
powershell -ExecutionPolicy Bypass -File tools\build_apk.ps1
# 产物: apps\camera_guard\build\app\outputs\flutter-apk\app-release.apk
adb install app-release.apk
```

App 使用：打开 → 拍摄（首次启动自动生成签名密钥，私钥不可导出）→ 自动签名 → 结果页显示哈希/签名 → 分享 `.sgd` → 任何人在 App 或 CLI 中验证。

## CLI 快速上手

```powershell
python src\simple_guard.py genkey --dir demo\out_simple
python src\simple_guard.py sign demo\out_simple\sample.mp4 demo\out_simple\sample.sgd --privkey demo\out_simple\identity.key
python src\simple_guard.py verify demo\out_simple\sample.sgd --pubkey demo\out_simple\identity.pub   # 0=一致 1=被改动
python src\simple_guard.py check demo\out_simple\watermark.mp4 --sigfile demo\out_simple\sample.sgd
```

## 实测结果

- 10 类攻击（1 字节翻转 / 加水印 / 改色 / 遮挡 / 插入 / 拼接 / 换音轨 / 掉包 / 改容器 / 聪明攻击）全部检出：[demo/out_simple/report.md](demo/out_simple/report.md)
- Dart 包 13 项单测全绿（RFC 8032 向量、流式、增量、与 Python 双向互通）
- 超大文件基准：2 GB 流式哈希，桌面 JIT 173 MiB/s、内存 O(1)；App 内后台 isolate + 进度条，签名过程不卡 UI

## 测试与构建状态

```powershell
cd packages\simple_guard_dart; dart test        # 13/13
cd apps\camera_guard; flutter analyze; flutter test   # 7/7
```
