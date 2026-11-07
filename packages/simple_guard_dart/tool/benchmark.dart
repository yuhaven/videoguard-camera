/// 大文件哈希性能基准：dart run tool/benchmark.dart <file> [chunkSizeMiB]
/// 输出 大小 / 耗时 / 吞吐（MiB/s）。
import 'dart:io';

import 'package:simple_guard_dart/simple_guard.dart';

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.writeln('usage: dart run tool/benchmark.dart <file> [chunkSizeMiB]');
    exit(1);
  }
  final path = args[0];
  final chunkSize = (args.length > 1 ? int.parse(args[1]) : 4) * 1024 * 1024;
  final file = File(path);
  if (!file.existsSync()) {
    stderr.writeln('file not found: $path');
    exit(1);
  }
  final size = file.lengthSync();
  final sw = Stopwatch()..start();
  final digest = sha256File(path, chunkSize: chunkSize);
  sw.stop();
  final mb = size / (1024 * 1024);
  final secs = sw.elapsedMicroseconds / 1e6;
  stdout.writeln('file  : $path');
  stdout.writeln('size  : ${mb.toStringAsFixed(1)} MiB (chunk ${chunkSize ~/ (1024 * 1024)} MiB)');
  stdout.writeln('digest: $digest');
  stdout.writeln('time  : ${secs.toStringAsFixed(3)} s');
  stdout.writeln('speed : ${(mb / secs).toStringAsFixed(1)} MiB/s');
}
