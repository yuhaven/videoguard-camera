import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../services/key_service.dart';

/// 设置：公钥导出（文本 + 二维码）、密钥重置、算法说明。
class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, this.keyService});

  final KeyService? keyService;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late final KeyService _keys = widget.keyService ?? KeyService();
  String? _pubkey;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final pub = await _keys.publicKeyB64();
    if (mounted) setState(() => _pubkey = pub);
  }

  Future<void> _reset() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('重置签名密钥？'),
        content: const Text(
            '将生成新密钥。已签名的文件用旧公钥仍可验证；新拍摄将用新密钥签名。'),
        actions: [
          TextButton(
              onPressed: () => Navigator.of(ctx).pop(false),
              child: const Text('取消')),
          FilledButton(
              onPressed: () => Navigator.of(ctx).pop(true),
              child: const Text('重置')),
        ],
      ),
    );
    if (ok == true) {
      await _keys.reset();
      await _load();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('已生成新密钥')));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('设置')),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          const Text('验证公钥（可公开，供他人验证你拍摄的内容）',
              style: TextStyle(fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          if (_pubkey == null)
            const Center(child: CircularProgressIndicator())
          else ...[
            Center(
              child: QrImageView(
                data: _pubkey!,
                version: QrVersions.auto,
                size: 180,
              ),
            ),
            const SizedBox(height: 12),
            SelectableText(_pubkey!,
                style: const TextStyle(fontSize: 11, fontFamily: 'monospace')),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              icon: const Icon(Icons.copy),
              label: const Text('复制公钥'),
              onPressed: () async {
                await Clipboard.setData(ClipboardData(text: _pubkey!));
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('公钥已复制')));
                }
              },
            ),
          ],
          const Divider(height: 40),
          const Text('密钥管理', style: TextStyle(fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          const Text('私钥在首次启动时自动生成，保存在设备安全区（Android Keystore / iOS Keychain），不可导出 —— 保证无人能伪造你的签名。',
              style: TextStyle(fontSize: 12, color: Colors.black54)),
          const SizedBox(height: 12),
          OutlinedButton.icon(
            icon: const Icon(Icons.refresh),
            label: const Text('重置密钥'),
            onPressed: _reset,
          ),
          const Divider(height: 40),
          const Text('算法说明', style: TextStyle(fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          const Text(
            'SimpleGuard（极简防篡改，三步）：\n'
            '① H = SHA-256(整个文件)\n'
            '② S = Ed25519 私钥签名(H)（非对称）\n'
            '③ 验证：重算哈希 + 公钥验签\n\n'
            '任何 1 字节改动 → 哈希必变 → 检出；\n'
            '没有私钥 → 无法伪造签名 → 掉包必识破。',
            style: TextStyle(fontSize: 13, height: 1.6),
          ),
        ],
      ),
    );
  }
}
