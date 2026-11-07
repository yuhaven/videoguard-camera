import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../services/guard_service.dart';
import '../services/key_service.dart';

/// 验证页：验证 .sgd 容器，或用签名包验证任意文件副本。
class VerifyScreen extends StatefulWidget {
  const VerifyScreen({super.key});

  @override
  State<VerifyScreen> createState() => _VerifyScreenState();
}

class _VerifyScreenState extends State<VerifyScreen> {
  String? _sigfile;
  String? _result;
  bool _resultOk = false;
  bool _busy = false;

  Future<void> _pickSgd() async {
    final picked = await FilePicker.platform.pickFiles();
    if (picked == null || picked.files.isEmpty) return;
    await _run(() => GuardService(KeyService())
        .verifySgdFile(picked.files.single.path!));
  }

  Future<void> _pickSigfile() async {
    final picked = await FilePicker.platform.pickFiles();
    if (picked == null || picked.files.isEmpty) return;
    setState(() => _sigfile = picked.files.single.path);
  }

  Future<void> _pickFileToCheck() async {
    final sig = _sigfile;
    if (sig == null) {
      _toast('请先选择签名包（.sgd）');
      return;
    }
    final picked = await FilePicker.platform.pickFiles();
    if (picked == null || picked.files.isEmpty) return;
    await _run(() => GuardService(KeyService())
        .checkFile(filePath: picked.files.single.path!, sigfilePath: sig));
  }

  Future<void> _run(Future<dynamic> Function() fn) async {
    setState(() => _busy = true);
    try {
      final outcome = await fn();
      if (!mounted) return;
      setState(() {
        _resultOk = outcome.isClean;
        _result = outcome.isClean
            ? outcome.message
            : '${outcome.message}'
                '${outcome.actualSha256.isEmpty ? '' : '\n原始 SHA-256: ${outcome.expectedSha256}\n当前 SHA-256: ${outcome.actualSha256}'}';
      });
    } catch (e) {
      if (mounted) {
        setState(() {
          _resultOk = false;
          _result = '验证失败: $e';
        });
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _toast(String s) {
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(s), duration: const Duration(seconds: 2)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('验证')),
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text('任何一点改动（加水印/改色/遮挡/剪辑/换音轨/重编码）都会检出。',
                style: TextStyle(fontSize: 12, color: Colors.black54)),
            const SizedBox(height: 16),
            FilledButton.icon(
              icon: const Icon(Icons.fact_check_outlined),
              label: const Text('验证 .sgd 签名容器'),
              onPressed: _busy ? null : _pickSgd,
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              icon: const Icon(Icons.description_outlined),
              label: Text(_sigfile == null
                  ? '选择签名包（用于验证任意副本）'
                  : '签名包: ${_sigfile!.split(Platform.pathSeparator).last}'),
              onPressed: _busy ? null : _pickSigfile,
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              icon: const Icon(Icons.video_file_outlined),
              label: const Text('选择待验证的视频/文件'),
              onPressed: (_busy || _sigfile == null) ? null : _pickFileToCheck,
            ),
            const SizedBox(height: 20),
            if (_busy) const Center(child: CircularProgressIndicator()),
            if (_result != null)
              Card(
                color: _resultOk ? Colors.green.shade50 : Colors.red.shade50,
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(
                              _resultOk ? Icons.verified : Icons.gpp_bad,
                              color: _resultOk ? Colors.green : Colors.redAccent),
                          const SizedBox(width: 8),
                          Text(_resultOk ? '验证通过：完全一致' : '检出改动',
                              style: TextStyle(
                                  fontWeight: FontWeight.bold,
                                  color: _resultOk
                                      ? Colors.green.shade800
                                      : Colors.red.shade800)),
                        ],
                      ),
                      const SizedBox(height: 8),
                      SelectableText(_result!,
                          style: const TextStyle(
                              fontSize: 12, fontFamily: 'monospace')),
                    ],
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
