import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:simple_guard_dart/simple_guard.dart';
import 'package:test/test.dart';

void main() {
  group('SHA-256 流式哈希', () {
    test('已知向量 abc', () {
      final payload = utf8.encode('abc');
      final f = _tmp('abc.bin')..writeAsBytesSync(payload);
      // 1 字节分块与整块结果一致
      final d1 = sha256File(f.path, chunkSize: 1);
      final d2 = sha256File(f.path);
      expect(d1, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
      expect(d2, d1);
    });

    test('偏移起点哈希（容器视频区）', () {
      final payload = utf8.encode('hello world');
      final f = _tmp('off.bin')
        ..writeAsBytesSync([...ascii.encode('SGD1'), ...payload]);
      final plain = _tmp('hello.bin')..writeAsBytesSync(payload);
      expect(sha256File(f.path, offset: 4), sha256File(plain.path));
    });

    test('进度回调完整覆盖', () {
      final f = _tmp('prog.bin')
        ..writeAsBytesSync(Uint8List.fromList(List.generate(10 * 1024 * 1024, (i) => i % 251)));
      var lastDone = 0;
      final d = sha256File(f.path, chunkSize: 1024 * 1024, onProgress: (d, t) {
        expect(d, greaterThanOrEqualTo(lastDone));
        lastDone = d;
        expect(t, 10 * 1024 * 1024);
      });
      expect(lastDone, 10 * 1024 * 1024);
      expect(d, isNotEmpty);
    });
    test('增量哈希器：分次喂入 == 一次性哈希', () {
      final data = Uint8List.fromList(List.generate(5 * 1024 * 1024, (i) => i % 251));
      final f = _tmp('inc.bin')..writeAsBytesSync(data);
      final oneShot = sha256File(f.path);

      final inc = IncrementalSha256();
      var off = 0;
      while (off < data.length) {
        final end = (off + 997 * 1024).clamp(0, data.length);
        inc.add(data.sublist(off, end));
        off = end;
      }
      expect(inc.closeAndDigestHex(), oneShot);
    });

    test('增量哈希器关闭后不可再喂入', () {
      final inc = IncrementalSha256();
      inc.add([1, 2, 3]);
      inc.closeAndDigestHex();
      expect(() => inc.add([4]), throwsStateError);
    });
  });

  group('Ed25519 非对称签名', () {
    test('RFC 8032 测试向量（与 Python cryptography 互通基础）', () {
      final seed = Uint8List.fromList(_hexToBytes(
          '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'));
      final sig = signDigest(seed, Uint8List(0));
      expect(_hex(sig), 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555'
          'fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
      final kp = keyPairFromSeed(seed);
      expect(_hex(kp.publicKey),
          'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    });

    test('签名往返 + 篡改检出', () {
      final kp = generateKeyPair();
      final digest = Uint8List.fromList(_hexToBytes(
          'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'));
      final sig = signDigest(kp.seed, digest);
      expect(verifySignature(publicKey: kp.publicKey, signature: sig, digest: digest), isTrue);
      final bad = Uint8List.fromList(digest)..[0] ^= 0x01;
      expect(verifySignature(publicKey: kp.publicKey, signature: sig, digest: bad), isFalse);
      final badSig = Uint8List.fromList(sig)..[10] ^= 0x01;
      expect(verifySignature(publicKey: kp.publicKey, signature: badSig, digest: digest), isFalse);
      // 非法长度
      expect(verifySignature(publicKey: Uint8List(5), signature: sig, digest: digest), isFalse);
    });
  });

  group('.sgd 打包 / 验证 / 取出', () {
    late Directory dir;
    late String videoPath;
    late Uint8List seed;

    setUp(() {
      dir = Directory.systemTemp.createTempSync('sgd-test-');
      videoPath = '${dir.path}${Platform.pathSeparator}video.bin';
      File(videoPath).writeAsBytesSync(
          Uint8List.fromList(List.generate(300 * 1024, (i) => i * 7 % 256)));
      seed = Uint8List.fromList(List.generate(32, (i) => i * 3 + 1));
    });

    tearDown(() => dir.deleteSync(recursive: true));

    test('打包后验证 PASS；取出与原文件一致', () {
      final sgd = '${dir.path}${Platform.pathSeparator}v.sgd';
      packSgd(videoPath: videoPath, seed: seed, outPath: sgd);
      final r = verifySgd(sgd);
      expect(r.verdict, 'PASS', reason: r.message);

      final ex = '${dir.path}${Platform.pathSeparator}extracted.bin';
      extractVideo(sgd, ex);
      expect(File(ex).readAsBytesSync(), File(videoPath).readAsBytesSync());
    });

    test('改 1 字节 → TAMPERED', () {
      final sgd = '${dir.path}${Platform.pathSeparator}v.sgd';
      packSgd(videoPath: videoPath, seed: seed, outPath: sgd);
      final bytes = File(sgd).readAsBytesSync();
      bytes[bytes.length - 10] ^= 0x01; // 视频区 1 字节
      final tampered = '${dir.path}${Platform.pathSeparator}t.sgd';
      File(tampered).writeAsBytesSync(bytes);
      final r = verifySgd(tampered);
      expect(r.verdict, 'TAMPERED', reason: r.message);
      expect(r.actualSha256, isNot(r.expectedSha256));
    });

    test('改视频并同步改哈希（无签名私钥）→ SIGNATURE_INVALID', () {
      final sgd = '${dir.path}${Platform.pathSeparator}v.sgd';
      packSgd(videoPath: videoPath, seed: seed, outPath: sgd);
      final raf = File(sgd).openSync();
      final magic = raf.readSync(4);
      final hlen = ByteData.sublistView(raf.readSync(4)).getUint32(0);
      final header = jsonDecode(utf8.decode(raf.readSync(hlen))) as Map<String, dynamic>;
      raf.closeSync();

      final newVideo = Uint8List.fromList(List.generate(1024, (i) => i % 200));
      final newDigest = sha256File(_tmpBytes(newVideo));
      header['sha256'] = newDigest;
      header['size'] = newVideo.length;
      final hj = utf8.encode(jsonEncode(header));
      final forged = '${dir.path}${Platform.pathSeparator}f.sgd';
      File(forged).writeAsBytesSync([
        ...magic,
        ...(ByteData(4)..setUint32(0, hj.length)).buffer.asUint8List(),
        ...hj,
        ...newVideo,
      ]);
      final r = verifySgd(forged);
      expect(r.verdict, 'SIGNATURE_INVALID', reason: r.message);
    });

    test('checkFile 验证任意副本：原文件 PASS，改动后 TAMPERED', () {
      final sgd = '${dir.path}${Platform.pathSeparator}v.sgd';
      packSgd(videoPath: videoPath, seed: seed, outPath: sgd);
      expect(checkFile(filePath: videoPath, sigfilePath: sgd).verdict, 'PASS');
      final modified = '${dir.path}${Platform.pathSeparator}m.bin';
      final b = File(videoPath).readAsBytesSync();
      b[0] ^= 0x01;
      File(modified).writeAsBytesSync(b);
      expect(checkFile(filePath: modified, sigfilePath: sgd).verdict, 'TAMPERED');
    });
  });

  group('与 Python CLI 双向互通', () {
    final fixtures = Directory('test/fixtures');
    final python = Platform.environment['VG_PYTHON'];

    test('Python 生成的 .sgd → Dart 验证 PASS / 篡改检出', () {
      expect(fixtures.existsSync(), isTrue,
          reason: '缺少 test/fixtures（运行 demo 前先由 Python 生成）');
      final ok = '${fixtures.path}${Platform.pathSeparator}ok.sgd';
      expect(verifySgd(ok).verdict, 'PASS');

      final tampered = '${fixtures.path}${Platform.pathSeparator}tampered.sgd';
      expect(verifySgd(tampered).verdict, 'TAMPERED');

      final forged = '${fixtures.path}${Platform.pathSeparator}forged.sgd';
      expect(verifySgd(forged).verdict, 'SIGNATURE_INVALID');

      // 用公开密钥文件验证任意副本
      final pubFile = '${fixtures.path}${Platform.pathSeparator}identity.pub';
      if (File(pubFile).existsSync()) {
        final pubRaw = _pubRawFromPem(File(pubFile).readAsStringSync());
        final payload = '${fixtures.path}${Platform.pathSeparator}payload.bin';
        expect(
            checkFile(filePath: payload, sigfilePath: ok, publicKey: pubRaw).verdict,
            'PASS');
      }
    }, skip: python == null ? false : null);

    test('Dart 生成的 .sgd → Python verify 通过 / 篡改被 Python 检出', () {
      if (python == null) {
        markTestSkipped('未设置 VG_PYTHON，跳过反向互通');
        return;
      }
      final dir = Directory.systemTemp.createTempSync('sgd-interop-');
      addTearDown(() => dir.deleteSync(recursive: true));
      final video = '${dir.path}${Platform.pathSeparator}v.bin';
      File(video).writeAsBytesSync(
          Uint8List.fromList(List.generate(64 * 1024, (i) => (i * 13) % 256)));
      final sgd = '${dir.path}${Platform.pathSeparator}v.sgd';
      packSgd(videoPath: video, seed: Uint8List.fromList(List.generate(32, (i) => i)), outPath: sgd);

      String cli = '';
      for (final base in [Directory.current.parent.parent, Directory.current.parent]) {
        final p = '${base.path}${Platform.pathSeparator}src'
            '${Platform.pathSeparator}simple_guard.py';
        if (File(p).existsSync()) {
          cli = p;
          break;
        }
      }
      expect(cli, isNotEmpty);

      // 干净容器 → Python exit 0
      final r1 = Process.runSync(python, [cli, 'verify', sgd], runInShell: false);
      expect(r1.exitCode, 0, reason: '${r1.stdout}\n${r1.stderr}');

      // 篡改 1 字节 → Python exit 1
      final bytes = File(sgd).readAsBytesSync();
      bytes[bytes.length - 5] ^= 0x01;
      final bad = '${dir.path}${Platform.pathSeparator}bad.sgd';
      File(bad).writeAsBytesSync(bytes);
      final r2 = Process.runSync(python, [cli, 'verify', bad]);
      expect(r2.exitCode, 1, reason: '${r2.stdout}\n${r2.stderr}');
    });
  });
}

File _tmp(String name) {
  final dir = Directory.systemTemp.createTempSync('sgd-hash-');
  addTearDown(() => dir.deleteSync(recursive: true));
  return File('${dir.path}${Platform.pathSeparator}$name');
}

String _tmpBytes(List<int> bytes) {
  final f = File('${Directory.systemTemp.createTempSync('sgd-b').path}'
      '${Platform.pathSeparator}x.bin');
  f.writeAsBytesSync(bytes);
  return f.path;
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

List<int> _hexToBytes(String hex) {
  final out = <int>[];
  for (var i = 0; i + 1 < hex.length; i += 2) {
    out.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }
  return out;
}

/// 从 PEM SubjectPublicKeyInfo 里取最后 32 字节（Ed25519 原始公钥）。
Uint8List _pubRawFromPem(String pem) {
  final b64 = pem
      .replaceAll('-----BEGIN PUBLIC KEY-----', '')
      .replaceAll('-----END PUBLIC KEY-----', '')
      .replaceAll(RegExp(r'\s'), '');
  final der = base64Decode(b64);
  return Uint8List.fromList(der.sublist(der.length - 32));
}
