/// SimpleGuard —— 极简非对称签名防篡改核心（与 `src/simple_guard.py` 字节级互通）
///
/// 算法三步:
///   ① H = SHA-256(整个文件，流式分块)
///   ② S = Ed25519 私钥签名(H)（非对称：私钥签、公钥验）
///   ③ 验证: 重算 H'，H'==H 且公钥验签通过 → 完全一致；否则 → 检出改动
///
/// 保证: SHA-256 抗碰撞（改 1 字节哈希必变）+ Ed25519 无私钥无法伪造
///       → 加水印/改色/遮挡/插入/拼接/换音轨/重编码，一切字节变化全部检出。
///
/// .sgd 容器布局（与 Python 版一致）:
///   [0..4)  MAGIC "SGD1"
///   [4..8)  header_len  (u32 大端)
///   [8..8+hlen)  header JSON（utf-8）
///   之后    视频原始字节（一字未动）
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed25519;

/// 容器 magic（与 Python 版 `simple_guard.py` 一致）。
const String sgdMagic = 'SGD1';

/// 默认分块大小（4 MiB）。
const int defaultChunkSize = 4 * 1024 * 1024;

/// 生成 Ed25519 密钥对。seed 为空时用密码学安全随机数。
class KeyPair {
  KeyPair({required this.seed, required this.publicKey});

  /// 32 字节种子（私钥材料）。
  final Uint8List seed;

  /// 32 字节原始公钥。
  final Uint8List publicKey;

  String get seedB64 => base64Encode(seed);
  String get publicKeyB64 => base64Encode(publicKey);
}

KeyPair generateKeyPair() {
  final rnd = Random.secure();
  final seed = Uint8List.fromList(
      List<int>.generate(32, (_) => rnd.nextInt(256)));
  return keyPairFromSeed(seed);
}

KeyPair keyPairFromSeed(Uint8List seed) {
  final priv = ed25519.newKeyFromSeed(seed);
  return KeyPair(
      seed: seed, publicKey: Uint8List.fromList(priv.bytes.sublist(32)));
}

/// 用种子对 32 字节摘要签名，返回 64 字节签名。
Uint8List signDigest(Uint8List seed, Uint8List digest) {
  final priv = ed25519.newKeyFromSeed(seed);
  return ed25519.sign(priv, digest);
}

/// 公钥验签；公钥或签名长度非法返回 false。
bool verifySignature({
  required Uint8List publicKey,
  required Uint8List signature,
  required Uint8List digest,
}) {
  if (publicKey.length != 32 || signature.length != 64) return false;
  try {
    return ed25519.verify(ed25519.PublicKey(publicKey.toList()), digest, signature);
  } catch (_) {
    return false;
  }
}

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// 收集 `crypto` 包流式哈希最终 Digest 的 Sink。
class _DigestSink implements Sink<Digest> {
  Digest? digest;
  @override
  void add(Digest data) => digest = data;
  @override
  void close() {}
}

/// 流式计算文件 SHA-256（O(1) 内存），支持进度回调与偏移起点。
String sha256File(
  String path, {
  int chunkSize = defaultChunkSize,
  int offset = 0,
  void Function(int doneBytes, int totalBytes)? onProgress,
}) {
  final raf = File(path).openSync();
  try {
    raf.setPositionSync(offset);
    final total = raf.lengthSync();
    final sink = _DigestSink();
    final input = sha256.startChunkedConversion(sink);
    var done = offset;
    try {
      while (true) {
        final buf = raf.readSync(chunkSize);
        if (buf.isEmpty) break;
        input.add(buf);
        done += buf.length;
        onProgress?.call(done - offset, total - offset);
      }
      input.close();
    } catch (_) {
      try {
        input.close();
      } catch (_) {}
      rethrow;
    }
    return _hex(Uint8List.fromList(sink.digest!.bytes));
  } finally {
    raf.closeSync();
  }
}

/// 容器头（与 Python 版字段一致）。
class SgdHeader {
  SgdHeader({
    required this.sha256,
    required this.signature,
    required this.pubkey,
    required this.size,
    this.createdAt = '',
  });

  final String sha256; // 视频部分 SHA-256（hex）
  final String signature; // base64，64 字节
  final String pubkey; // base64，32 字节原始公钥
  final int size; // 视频字节数
  final String createdAt;

  Map<String, dynamic> toJson() => {
        'format': 'simple-guard/1',
        'algorithm': 'ed25519',
        'sha256': sha256,
        'signature': signature,
        'pubkey': pubkey,
        'size': size,
        'created_at': createdAt.isEmpty
            ? DateTime.now().toUtc().toIso8601String().split('.').first
            : createdAt,
      };

  static SgdHeader fromJson(Map<String, dynamic> j) => SgdHeader(
        sha256: j['sha256'] as String,
        signature: j['signature'] as String,
        pubkey: j['pubkey'] as String,
        size: (j['size'] as num).toInt(),
        createdAt: (j['created_at'] as String?) ?? '',
      );
}

/// 读取容器头，返回 (header, 视频数据起始偏移)。
(SgdHeader, int) readHeader(String sgdPath) {
  final raf = File(sgdPath).openSync();
  try {
    final magic = String.fromCharCodes(raf.readSync(4));
    if (magic != sgdMagic) {
      throw const FormatException('不是 SimpleGuard 容器（magic 不符）');
    }
    final hlen = ByteData.sublistView(raf.readSync(4)).getUint32(0);
    final hj = utf8.decode(raf.readSync(hlen));
    final header = SgdHeader.fromJson(
        jsonDecode(hj) as Map<String, dynamic>);
    return (header, 8 + hlen);
  } finally {
    raf.closeSync();
  }
}

/// 签名并打包：流式哈希 → 私钥签名 → 写 header + 流式拷贝视频（不整读内存）。
/// [knownDigestHex] 提供时跳过重哈希（录制中已增量预哈希），打包后自检可兜底。
void packSgd({
  required String videoPath,
  required Uint8List seed,
  required String outPath,
  int chunkSize = defaultChunkSize,
  String? knownDigestHex,
  void Function(int doneBytes, int totalBytes)? onProgress,
}) {
  final kp = keyPairFromSeed(seed);
  final videoSize = File(videoPath).lengthSync();
  final digestHex = knownDigestHex ??
      sha256File(videoPath, chunkSize: chunkSize, onProgress: onProgress);
  final sig = signDigest(seed, Uint8List.fromList(_hexToBytes(digestHex)));
  final header = SgdHeader(
    sha256: digestHex,
    signature: base64Encode(sig),
    pubkey: base64Encode(kp.publicKey),
    size: videoSize,
  );
  final hj = utf8.encode(jsonEncode(header.toJson()));

  final out = File(outPath).openSync(mode: FileMode.write);
  final src = File(videoPath).openSync();
  try {
    out.writeFromSync(ascii.encode(sgdMagic));
    out.writeFromSync(
        (ByteData(4)..setUint32(0, hj.length)).buffer.asUint8List());
    out.writeFromSync(hj);
    var done = 0;
    while (true) {
      final buf = src.readSync(chunkSize);
      if (buf.isEmpty) break;
      out.writeFromSync(buf);
      done += buf.length;
      onProgress?.call(done, videoSize);
    }
  } finally {
    src.closeSync();
    out.closeSync();
  }
}

/// 验证结果。
class VerifyOutcome {
  VerifyOutcome({required this.verdict, required this.message,
      this.expectedSha256 = '', this.actualSha256 = ''});

  /// PASS / TAMPERED / SIGNATURE_INVALID
  final String verdict;
  final String message;
  final String expectedSha256;
  final String actualSha256;

  bool get isClean => verdict == 'PASS';
}

/// 验证 .sgd 容器：重算哈希 → 比对 → 公钥验签。
/// 任何 1 字节改动 → 哈希不符（TAMPERED）；改视频并同步改哈希 → 签名无效。
VerifyOutcome verifySgd(String sgdPath, {Uint8List? publicKey}) {
  try {
    final (header, off) = readHeader(sgdPath);
    final actual = sha256File(sgdPath, offset: off);
    return _judge(header, actual, publicKey);
  } on FormatException catch (e) {
    return VerifyOutcome(
        verdict: 'TAMPERED', message: '容器被破坏或不是有效签名包: ${e.message}');
  }
}

/// 用 .sgd 中记录的哈希+签名验证任意文件副本。
VerifyOutcome checkFile({
  required String filePath,
  required String sigfilePath,
  Uint8List? publicKey,
}) {
  try {
    final (header, _) = readHeader(sigfilePath);
    final actual = sha256File(filePath);
    return _judge(header, actual, publicKey);
  } on FormatException catch (e) {
    return VerifyOutcome(
        verdict: 'TAMPERED', message: '签名包异常: ${e.message}');
  }
}

VerifyOutcome _judge(SgdHeader header, String actual, Uint8List? publicKey) {
  if (actual != header.sha256) {
    return VerifyOutcome(
      verdict: 'TAMPERED',
      message: '检出改动: 文件哈希与原始签名不符（哪怕只改 1 个字节也会报警）',
      expectedSha256: header.sha256,
      actualSha256: actual,
    );
  }
  final pub = publicKey ?? base64Decode(header.pubkey);
  final ok = verifySignature(
    publicKey: Uint8List.fromList(pub),
    signature: Uint8List.fromList(base64Decode(header.signature)),
    digest: Uint8List.fromList(_hexToBytes(header.sha256)),
  );
  if (!ok) {
    return VerifyOutcome(
      verdict: 'SIGNATURE_INVALID',
      message: '签名无效: 哈希对得上但签名不合法（伪造签名 / 掉包）',
      expectedSha256: header.sha256,
      actualSha256: actual,
    );
  }
  return VerifyOutcome(
      verdict: 'PASS', message: '完全一致: 文件未有任何改动，签名有效');
}

/// 从 .sgd 取出原始视频（流式拷贝）。
void extractVideo(String sgdPath, String outPath,
    {int chunkSize = defaultChunkSize,
    void Function(int doneBytes, int totalBytes)? onProgress}) {
  final (header, off) = readHeader(sgdPath);
  final src = File(sgdPath).openSync();
  final out = File(outPath).openSync(mode: FileMode.write);
  try {
    src.setPositionSync(off);
    var done = 0;
    while (true) {
      final buf = src.readSync(chunkSize);
      if (buf.isEmpty) break;
      out.writeFromSync(buf);
      done += buf.length;
      onProgress?.call(done, header.size);
    }
  } finally {
    src.closeSync();
    out.closeSync();
  }
}

/// 增量 SHA-256 哈希器 —— 录制过程中把新写入的文件区间持续喂入，
/// 停止录制时只需 `closeAndDigestHex()` 即出最终哈希（近零等待）。
class IncrementalSha256 {
  IncrementalSha256() {
    _input = sha256.startChunkedConversion(_sink);
  }

  final _sink = _DigestSink();
  late final ByteConversionSink _input;
  bool _closed = false;

  void add(List<int> chunk) {
    if (_closed) throw StateError('已关闭的增量哈希器');
    _input.add(chunk);
  }

  /// 结束输入并返回最终 SHA-256（hex）。
  String closeAndDigestHex() {
    if (!_closed) {
      _input.close();
      _closed = true;
    }
    return _hex(Uint8List.fromList(_sink.digest!.bytes));
  }
}

List<int> _hexToBytes(String hex) {
  final out = <int>[];
  for (var i = 0; i + 1 < hex.length; i += 2) {
    out.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }
  return out;
}
