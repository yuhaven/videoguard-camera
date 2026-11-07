import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:camera_guard/services/guard_service.dart';
import 'package:camera_guard/services/key_service.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:simple_guard_dart/simple_guard.dart';

void _entry(SendPort p) => p.send('hi');

/// 探针：隔离区里只加载 simple_guard_dart（不 import flutter）。
void _packEntryProbe(Map<String, Object> args) {
  final p = args['port'] as SendPort;
  final video = args['video'] as String;
  final out = args['out'] as String;
  final seed = args['seed'] as Uint8List;
  try {
    packSgd(
      videoPath: video,
      seed: seed,
      outPath: out,
      knownDigestHex: sha256File(video),
    );
    p.send(['ok', verifySgd(out).verdict]);
  } catch (e) {
    p.send(['err', '$e']);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('Isolate.run sanity（checkFile 用的路径）', () async {
    final r = await Isolate.run(() => 'hi').timeout(const Duration(seconds: 5));
    expect(r, 'hi');
  });

  test('isolate 基础 sanity', () async {
    final rp = ReceivePort();
    final iso = await Isolate.spawn(_entry, rp.sendPort);
    final msg = await rp.first.timeout(const Duration(seconds: 5));
    expect(msg, 'hi');
    iso.kill(priority: Isolate.immediate);
  });

  test('isolate 内执行 packSgd 探针（无 flutter 依赖）', () async {
    final dir = Directory.systemTemp.createTempSync('iso-probe-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final video = '${dir.path}${Platform.pathSeparator}v.bin';
    File(video).writeAsBytesSync(
        Uint8List.fromList(List<int>.generate(1024 * 1024, (i) => i % 256)));
    final out = '${dir.path}${Platform.pathSeparator}v.sgd';
    final rp = ReceivePort();
    final iso = await Isolate.spawn(_packEntryProbe, <String, Object>{
      'port': rp.sendPort,
      'video': video,
      'out': out,
      'seed': Uint8List.fromList(List<int>.generate(32, (i) => i)),
    });
    final msg = await rp.first.timeout(const Duration(seconds: 15));
    iso.kill(priority: Isolate.immediate);
    expect(msg, isA<List>());
    expect((msg as List)[0], 'ok');
  });

  test('GuardService.signAndPack 全流程（真实现）', () async {
    final dir = Directory.systemTemp.createTempSync('iso-full-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final video = '${dir.path}${Platform.pathSeparator}v.bin';
    File(video).writeAsBytesSync(
        Uint8List.fromList(List<int>.generate(512 * 1024, (i) => i % 256)));
    final out = '${dir.path}${Platform.pathSeparator}v.sgd';
    final result = await GuardService(KeyService(MemoryKV()))
        .signAndPack(videoPath: video, outPath: out)
        .timeout(const Duration(seconds: 20));
    expect(result.ok, isTrue, reason: result.selfVerify);
    expect(result.selfVerify, 'PASS');
  });
}
