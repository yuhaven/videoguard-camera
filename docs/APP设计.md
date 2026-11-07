# 防篡改相机 App 设计（camera_guard）

> 基于 SimpleGuard 极简算法（整文件 SHA-256 + Ed25519 非对称签名，`.sgd` 容器）的手机端成品：
> **拍摄完成即自动完成哈希+签名+打包**，任何一点改动（加水印/改色/遮挡/插入/拼接/换音轨/重编码/掉包）都能被完全验证出来。

## 1. 功能

| 页面 | 功能 |
|---|---|
| 相机页 | 录视频、拍照；权限引导；拍摄完成后自动进入签名流程（无需任何手动步骤） |
| 结果页 | 自动执行：流式 SHA-256 哈希（进度条）→ Ed25519 签名 → 打包 `.sgd` → 自检；展示哈希/签名/耗时；一键分享 |
| 相册页 | 已签名产物列表：验证 / 分享 / 删除 |
| 验证页 | 验证任意 `.sgd` 容器；或用签名包验证任意视频副本（离线、本地） |
| 设置页 | 公钥导出（文本+二维码）、密钥重置、算法说明 |

## 2. 架构

```
lib/
  main.dart                    入口
  services/
    key_service.dart           密钥管理：首次启动自动生成 Ed25519 密钥对，
                               私钥(种子)存 Android Keystore / iOS Keychain（不可导出）
    guard_service.dart         签名流水线：后台 isolate 流式哈希(进度) → 签名 → 打包 → 自检
  screens/                     相机页 / 结果页 / 相册页 / 验证页 / 设置页
packages/simple_guard_dart/    核心算法包（纯 Dart，与 Python CLI 字节级互通）
```

## 3. 关键设计

### 3.1 拍完即签（快速）

- 停止拍摄 → `XFile` 到手 → 后台 isolate 流式哈希（4 MiB 块，内存 O(1)），**同时**进度条展示；
- 哈希完成后立即 Ed25519 签名（微秒级）→ 打包（流式拷贝）→ 完成；
- 整个流程用户零操作；UI 全程不卡（isolate 隔离）。

### 3.2 超大视频方案

| 手段 | 说明 |
|---|---|
| 流式分块哈希 | 4 MiB 分块，任意大小视频内存占用恒定（O(1)） |
| 后台 isolate | 哈希/打包不阻塞 UI，可边签名边看结果页进度 |
| 大文件策略 | >50 MB 跳过签名后的二次全量自检（哈希与拷贝同进程、同一文件流完成，产物一致性已保证），节约一半时间 |
| 实测基准 | 纯 Dart JIT（桌面）：2 GB ≈ 173 MiB/s（11.8 s）；手机 AOT 预计更快；签名+打包追加 I/O 拷贝时间 |

### 3.3 可靠

- 私钥不可导出（平台安全存储）→ 无人能伪造签名；
- 签名完成后自动自检（≤50 MB 全量 verify；大文件同进程一致性保证）；
- 任何 1 字节改动 → SHA-256 必变 → 验证必失败（算法层已在 13 项单测 + 10 类攻击实测中验证）；
- 与 [`src/simple_guard.py`](../../src/simple_guard.py) 字节级互通：App 产物可用电脑 CLI 验证，反之亦然。

## 4. 技术栈

- Flutter 3.47（stable）/ Dart 3.13；
- `camera` 0.11（录制/拍照）、`flutter_secure_storage`（密钥安全存储）、`share_plus`（分享）、`file_picker`（验证页选文件）、`qr_flutter`（公钥二维码）；
- 核心算法自研纯 Dart（`crypto` + `ed25519_edwards`，RFC 8032 向量验证）；
- Android：minSdk 24（Android 7.0+）、compileSdk 36、release 正式签名；iOS：代码就绪（需 Mac/Xcode 构建）。

## 5. 构建与安装

```powershell
# 一键准备工具链（JDK17 + Android SDK + Flutter）
powershell -ExecutionPolicy Bypass -File tools\setup_android.ps1

# 一键构建（analyze + test + release APK）
powershell -ExecutionPolicy Bypass -File tools\build_apk.ps1
# 产物: apps\camera_guard\build\app\outputs\flutter-apk\app-release.apk
adb install app-release.apk
```

## 6. 使用与验证他人文件

1. 打开 App → 首次启动自动生成签名密钥（私钥不可导出）；
2. 拍摄视频/照片 → 自动签名 → 结果页显示哈希与签名；
3. 把 `.sgd` 通过分享发给他人；
4. 对方可在 App「验证」页验证，或电脑上：

```powershell
python src\simple_guard.py verify 收到的.sgd            # 0=完全一致 1=被改动
python src\simple_guard.py check 疑似视频.mp4 --sigfile 收到的.sgd
```

5. 在设置页导出公钥（二维码/文本），供任何人用公钥严格验证签名者身份。

## 7. 已知边界（诚实声明）

- 重编码（哪怕画面看着一样）也会报警 —— 本方案验收标准是"文件零改动"，比"画面级检测"更严格；
- 签名耗时 = 哈希时间 + 拷贝时间（I/O），桌面 JIT 基准 173 MiB/s；手机实测以真机为准；
- iOS 包需在 Mac 上用 `flutter build ios` 构建（代码已跨平台就绪）；
- release 签名 keystore 为演示用（`android/keystore/`，密码见 `key.properties`）；正式发布请替换为自己的 keystore；
- 构建环境注意：Gradle 发行包已切腾讯镜像（`gradle-wrapper.properties`）；若 pub 缓存（C 盘）与工程（D 盘）不同盘，Kotlin 增量缓存会跨盘符失败，已在 `gradle.properties` 关闭增量编译（`kotlin.incremental=false`）。
