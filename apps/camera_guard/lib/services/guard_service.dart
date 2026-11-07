import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:simple_guard_dart/simple_guard.dart';

import 'key_service.dart';

/// 签名打包结果。
class SignResult {
  SignResult({
    required this.ok,
    required this.outPath,
    required this.sha256,
    required this.signature,
    required this.pubkey,
    required this.elapsedMs,
    required this.selfVerify,
    required this.size,
  });

  final bool ok;
  final String outPath;
  final String sha256;
  final String signature;
  final String pubkey;
  final int elapsedMs;

  /// PASS=完整自检通过；SKIP=大文件跳过二次全量校验（同进程流式哈希+拷贝保证一致）
  final String selfVerify;
  final int size;
}

class _PackRequest {
  _PackRequest(this.videoPath, this.outPath, this.seed, this.knownDigest,
      this.skipSelfVerify, this.sendPort);

  final String videoPath;
  final String outPath;
  final Uint8List seed;
  final String? knownDigest;
  final bool skipSelfVerify;
  final SendPort sendPort;
}

/// isolate 入口：流式哈希（带进度）→ 签名打包（带进度）→ 自检。
void _packEntry(_PackRequest req) {
  try {
    String digest;
    if (req.knownDigest == null) {
      digest = sha256File(req.videoPath, onProgress: (d, t) {
        req.sendPort.send(<Object>['p', d, t * 2]);
      });
    } else {
      digest = req.knownDigest!;
    }
    packSgd(
      videoPath: req.videoPath,
      seed: req.seed,
      outPath: req.outPath,
      knownDigestHex: digest,
      onProgress: (d, t) {
        req.sendPort.send(<Object>[
          'p',
          req.knownDigest == null ? t + d : d,
          req.knownDigest == null ? t * 2 : t,
        ]);
      },
    );
    if (!req.skipSelfVerify) {
      req.sendPort.send(<Object>['d', verifySgd(req.outPath).verdict]);
    } else {
      req.sendPort.send(<Object>['d', 'SKIP']);
    }
  } catch (e) {
    req.sendPort.send(<Object>['e', '$e']);
  }
}

/// isolate 入口：验证 .sgd 容器。
void _verifyEntry(List<Object> args) {
  final p = args[0] as SendPort;
  final path = args[1] as String;
  try {
    final v = verifySgd(path);
    p.send(<Object>['d', v.verdict, v.message, v.expectedSha256, v.actualSha256]);
  } catch (e) {
    p.send(<Object>['e', '$e']);
  }
}

/// isolate 入口：用签名包验证任意文件副本。
void _checkEntry(List<Object> args) {
  final p = args[0] as SendPort;
  final file = args[1] as String;
  final sig = args[2] as String;
  try {
    final v = checkFile(filePath: file, sigfilePath: sig);
    p.send(<Object>['d', v.verdict, v.message, v.expectedSha256, v.actualSha256]);
  } catch (e) {
    p.send(<Object>['e', '$e']);
  }
}

Future<VerifyOutcome> _runVerify(
    List<Object> args, void Function(List<Object>) entry) async {
  final rp = ReceivePort();
  await Isolate.spawn(entry, <Object>[rp.sendPort, ...args]);
  String verdict = 'ERR';
  String message = '';
  String expected = '';
  String actual = '';
  Object? error;
  await for (final msg in rp) {
    if (msg is List && msg.isNotEmpty) {
      if (msg[0] == 'd') {
        verdict = msg[1] as String;
        message = msg[2] as String;
        expected = msg[3] as String;
        actual = msg[4] as String;
        break;
      } else if (msg[0] == 'e') {
        error = msg[1];
        break;
      }
    }
  }
  rp.close();
  if (error != null) throw StateError('验证失败: $error');
  return VerifyOutcome(
      verdict: verdict,
      message: message,
      expectedSha256: expected,
      actualSha256: actual);
}

/// 签名流水线：哈希（后台 isolate + 进度）→ Ed25519 签名 → 打包 .sgd → 自检。
class GuardService {
  GuardService(this._keys);

  final KeyService _keys;

  /// [knownDigest] 提供时跳过重哈希；[skipSelfVerify] 用于超大文件
  /// （哈希与拷贝在同一进程内对同一文件流式完成，产物一致性已保证）。
  Future<SignResult> signAndPack({
    required String videoPath,
    required String outPath,
    String? knownDigest,
    bool skipSelfVerify = false,
    void Function(int doneBytes, int totalBytes)? onProgress,
  }) async {
    final seed = await _keys.ensureKey();
    final rp = ReceivePort();
    final sw = Stopwatch()..start();
    await Isolate.spawn(
      _packEntry,
      _PackRequest(videoPath, outPath, seed, knownDigest, skipSelfVerify,
          rp.sendPort),
    );
    var verdict = 'ERR';
    Object? error;
    await for (final msg in rp) {
      if (msg is List && msg.isNotEmpty) {
        if (msg[0] == 'p') {
          onProgress?.call(msg[1] as int, msg[2] as int);
        } else if (msg[0] == 'd') {
          verdict = msg[1] as String;
          break;
        } else if (msg[0] == 'e') {
          error = msg[1];
          break;
        }
      }
    }
    sw.stop();
    rp.close();
    if (error != null) {
      throw StateError('签名打包失败: $error');
    }
    final (header, _) = readHeader(outPath);
    return SignResult(
      ok: verdict == 'PASS' || verdict == 'SKIP',
      outPath: outPath,
      sha256: header.sha256,
      signature: header.signature,
      pubkey: header.pubkey,
      elapsedMs: sw.elapsedMilliseconds,
      selfVerify: verdict,
      size: File(outPath).lengthSync(),
    );
  }

  /// 验证 .sgd 容器（后台 isolate）。
  Future<VerifyOutcome> verifySgdFile(String path) async =>
      _runVerify(<Object>[path], _verifyEntry);

  /// 用签名包验证任意文件副本。
  Future<VerifyOutcome> checkFile({
    required String filePath,
    required String sigfilePath,
  }) async =>
      _runVerify(<Object>[filePath, sigfilePath], _checkEntry);
}
