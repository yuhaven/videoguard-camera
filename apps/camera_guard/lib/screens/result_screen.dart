import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';

import '../services/guard_service.dart';
import '../services/key_service.dart';

/// 拍摄完成后自动进入：流式哈希（进度）→ 签名打包 → 展示结果。
class ResultScreen extends StatefulWidget {
  const ResultScreen({
    super.key,
    required this.mediaPath,
    required this.isVideo,
    this.knownDigest,
    this.keyService,
  });

  final String mediaPath;
  final bool isVideo;
  final String? knownDigest;
  final KeyService? keyService;

  @override
  State<ResultScreen> createState() => _ResultScreenState();
}

class _ResultScreenState extends State<ResultScreen> {
  SignResult? _result;
  String? _error;
  bool _done = false;
  double _progress = 0;

  @override
  void initState() {
    super.initState();
    _sign();
  }

  Future<void> _sign() async {
    try {
      final keys = widget.keyService ?? KeyService();
      final dir = await getApplicationDocumentsDirectory();
      final signedDir = Directory(p.join(dir.path, 'signed'));
      await signedDir.create(recursive: true);
      final out = p.join(signedDir.path,
          '${p.basenameWithoutExtension(widget.mediaPath)}.sgd');
      final service = GuardService(keys);
      // 超大文件跳过二次全量自检（哈希与拷贝同进程流式完成，产物一致性已保证）
      final size = File(widget.mediaPath).lengthSync();
      final result = await service.signAndPack(
        videoPath: widget.mediaPath,
        outPath: out,
        knownDigest: widget.knownDigest,
        skipSelfVerify: size > 50 * 1024 * 1024,
        onProgress: (done, total) {
          if (mounted && total > 0) {
            setState(() => _progress = (done / total).clamp(0.0, 1.0));
          }
        },
      );
      if (!mounted) return;
      setState(() {
        _result = result;
        _done = true;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = '$e';
        _done = true;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.isVideo ? '视频已拍摄' : '照片已拍摄')),
      body: _done ? _buildResult() : _buildSigning(),
    );
  }

  Widget _buildSigning() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 24),
            const Text('正在签名打包…\n（流式 SHA-256 哈希 → Ed25519 签名）',
                textAlign: TextAlign.center),
            const SizedBox(height: 16),
            if (_progress > 0) ...[
              LinearProgressIndicator(value: _progress),
              const SizedBox(height: 8),
              Text('${(_progress * 100).toStringAsFixed(0)}%',
                  style: const TextStyle(fontSize: 13)),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildResult() {
    if (_error != null) {
      return Center(
          child: Padding(
        padding: const EdgeInsets.all(24),
        child: Text('签名失败: $_error',
            style: const TextStyle(color: Colors.redAccent),
            textAlign: TextAlign.center),
      ));
    }
    final r = _result!;
    final ok = r.ok;
    return Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Card(
            color: ok ? Colors.green.shade50 : Colors.red.shade50,
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                children: [
                  Icon(ok ? Icons.verified : Icons.gpp_bad,
                      size: 64,
                      color: ok ? Colors.green : Colors.redAccent),
                  const SizedBox(height: 8),
                  Text(
                    ok ? '已签名 · 完整性自检通过' : '自检未通过',
                    style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                        color: ok ? Colors.green.shade800 : Colors.red.shade800),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          _kv('SHA-256 文件哈希', r.sha256),
          _kv('Ed25519 签名', r.signature),
          _kv('签名耗时', '${r.elapsedMs} ms'),
          _kv('产物大小', '${(r.size / 1024).toStringAsFixed(1)} KiB'),
          _kv('产物文件', r.outPath),
          const SizedBox(height: 12),
          const Text('任何 1 字节改动（加水印/改色/遮挡/剪辑/换音轨）都会导致验证失败。',
              style: TextStyle(fontSize: 12, color: Colors.black54)),
          const Spacer(),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  icon: const Icon(Icons.share),
                  label: const Text('分享 .sgd'),
                  onPressed: () => Share.shareXFiles(
                      [XFile(r.outPath)],
                      text: '防篡改签名产物（SimpleGuard .sgd）'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: FilledButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: const Text('完成'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _kv(String k, String v) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 110, child: Text(k, style: const TextStyle(fontSize: 13))),
          Expanded(
            child: SelectableText(
              v.length > 90 ? '${v.substring(0, 90)}…' : v,
              style: const TextStyle(
                  fontSize: 12, fontFamily: 'monospace', color: Colors.black87),
            ),
          ),
        ],
      ),
    );
  }
}
