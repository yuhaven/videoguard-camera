import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';

import '../services/guard_service.dart';
import '../services/key_service.dart';

/// 已签名产物列表：验证 / 分享 / 删除。
class GalleryScreen extends StatefulWidget {
  const GalleryScreen({super.key});

  @override
  State<GalleryScreen> createState() => _GalleryScreenState();
}

class _GalleryScreenState extends State<GalleryScreen> {
  List<File> _files = [];

  @override
  void initState() {
    super.initState();
    _reload();
  }

  Future<void> _reload() async {
    final dir = await getApplicationDocumentsDirectory();
    final signedDir = Directory(p.join(dir.path, 'signed'));
    if (!signedDir.existsSync()) {
      setState(() => _files = []);
      return;
    }
    final files = signedDir
        .listSync()
        .whereType<File>()
        .where((f) => f.path.endsWith('.sgd'))
        .toList()
      ..sort((a, b) => b.statSync().modified.compareTo(a.statSync().modified));
    if (mounted) setState(() => _files = files);
  }

  Future<void> _verify(File f) async {
    final outcome = await GuardService(KeyService()).verifySgdFile(f.path);
    if (!mounted) return;
    final ok = outcome.isClean;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(ok ? '✓ 完全一致' : '✗ 检出改动'),
        content: Text(outcome.message +
            (outcome.actualSha256.isEmpty
                ? ''
                : '\n原始: ${outcome.expectedSha256}\n当前: ${outcome.actualSha256}')),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('关闭')),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('已签名产物')),
      body: _files.isEmpty
          ? const Center(child: Text('还没有签名产物。\n回到相机拍摄，拍摄完成即自动签名。',
              textAlign: TextAlign.center))
          : RefreshIndicator(
              onRefresh: _reload,
              child: ListView.builder(
                itemCount: _files.length,
                itemBuilder: (ctx, i) {
                  final f = _files[i];
                  final st = f.statSync();
                  return ListTile(
                    leading: const Icon(Icons.verified_outlined, color: Colors.teal),
                    title: Text(p.basename(f.path)),
                    subtitle: Text(
                        '${(st.size / 1024).toStringAsFixed(0)} KiB · ${st.modified.toLocal().toString().substring(0, 19)}'),
                    trailing: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        IconButton(
                            tooltip: '验证',
                            icon: const Icon(Icons.fact_check_outlined),
                            onPressed: () => _verify(f)),
                        IconButton(
                            tooltip: '分享',
                            icon: const Icon(Icons.share),
                            onPressed: () => Share.shareXFiles(
                                [XFile(f.path)],
                                text: '防篡改签名产物（SimpleGuard .sgd）')),
                        IconButton(
                            tooltip: '删除',
                            icon: const Icon(Icons.delete_outline),
                            onPressed: () async {
                              await f.delete();
                              _reload();
                            }),
                      ],
                    ),
                  );
                },
              ),
            ),
    );
  }
}
