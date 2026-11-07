import 'package:flutter/material.dart';

import 'screens/camera_screen.dart';
import 'services/key_service.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const CameraGuardApp());
}

/// 防篡改相机：拍摄完成即自动 SHA-256 哈希 + Ed25519 非对称签名，
/// 打包为 .sgd（与 simple_guard.py / simple_guard_dart 完全互通）。
class CameraGuardApp extends StatelessWidget {
  const CameraGuardApp({super.key, this.keyService});

  /// 测试注入用；默认首次启动在设备安全区自动生成密钥。
  final KeyService? keyService;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '防篡改相机',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(colorSchemeSeed: Colors.teal, useMaterial3: true),
      home: CameraScreen(keyService: keyService),
    );
  }
}
