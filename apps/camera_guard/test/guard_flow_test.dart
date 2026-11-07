import 'dart:io';
import 'dart:typed_data';

import 'package:camera_guard/services/guard_service.dart';
import 'package:camera_guard/services/key_service.dart';
import 'package:simple_guard_dart/simple_guard.dart';
import 'package:flutter_test/flutter_test.dart';

/// App 层"拍完即签"流程测试（不依赖相机硬件）：
/// 密钥生成 → 签名打包 → 自检 → 篡改检出 → 跨组件互通。
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('首次启动自动生成密钥且稳定复用', () async {
    final keys = KeyService(MemoryKV());
    final k1 = await keys.ensureKey();
    final k2 = await keys.ensureKey();
    expect(k1, k2);
    final pub = await keys.publicKeyB64();
    expect(pub.length, 44); // base64(32B)
    await keys.reset();
    final k3 = await keys.ensureKey();
    expect(k3, isNot(k1));
  });

  test('拍完即签：签名打包 + 自检通过 + 1 字节篡改检出', () async {
    final dir = Directory.systemTemp.createTempSync('app-flow-');
    addTearDown(() => dir.deleteSync(recursive: true));

    final video = File('${dir.path}${Platform.pathSeparator}clip.mp4');
    final bytes = Uint8List.fromList(
        List<int>.generate(5 * 1024 * 1024, (i) => (i * 31) % 256));
    video.writeAsBytesSync(bytes);

    final keys = KeyService(MemoryKV());
    final service = GuardService(keys);
    final out = '${dir.path}${Platform.pathSeparator}clip.sgd';

    // 录制中预哈希（App 里每 2 秒喂入一次）
    final pre = RecordingHasherCompat();
    final known = pre.hash(bytes);

    final result = await service
        .signAndPack(
            videoPath: video.path, outPath: out, knownDigest: known)
        .timeout(const Duration(seconds: 15));
    expect(result.ok, isTrue, reason: result.selfVerify);
    expect(result.sha256, known);
    expect(result.selfVerify, 'PASS');
    expect(result.elapsedMs, greaterThanOrEqualTo(0));

    // 产物可用 Python/CLI 侧逻辑（Dart 核心）验证
    expect(verifySgd(out).verdict, 'PASS');

    // 任何 1 字节改动 → 检出
    final tampered = File('${dir.path}${Platform.pathSeparator}bad.mp4');
    final bad = Uint8List.fromList(bytes)..[12345] ^= 0x01;
    tampered.writeAsBytesSync(bad);
    final verdict =
        await service.checkFile(filePath: tampered.path, sigfilePath: out);
    expect(verdict.verdict, 'TAMPERED');
  });
}

/// 轻量版增量哈希包装（验证 RecordingHasher 的等价逻辑在 VM 测试中可用）。
class RecordingHasherCompat {
  String hash(List<int> bytes) {
    final inc = IncrementalSha256();
    const chunk = 1024 * 1024;
    for (var i = 0; i < bytes.length; i += chunk) {
      inc.add(bytes.sublist(i, (i + chunk).clamp(0, bytes.length)));
    }
    return inc.closeAndDigestHex();
  }
}
