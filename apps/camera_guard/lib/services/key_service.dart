import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:simple_guard_dart/simple_guard.dart';

/// 极简键值安全存储抽象（测试可注入内存实现）。
abstract class SecureKV {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

/// 平台安全存储（Android Keystore 加密 / iOS Keychain）。
class FlutterSecureKV implements SecureKV {
  const FlutterSecureKV();
  final FlutterSecureStorage _storage = const FlutterSecureStorage();

  @override
  Future<String?> read(String key) => _storage.read(key: key);

  @override
  Future<void> write(String key, String value) =>
      _storage.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _storage.delete(key: key);
}

/// 内存实现（测试用）。
class MemoryKV implements SecureKV {
  final Map<String, String> _m = {};

  @override
  Future<String?> read(String key) async => _m[key];

  @override
  Future<void> write(String key, String value) async => _m[key] = value;

  @override
  Future<void> delete(String key) async => _m.remove(key);
}

/// 签名密钥管理：首次启动自动生成 Ed25519 密钥对；
/// 私钥（种子）只存设备安全区、不可导出；公钥可导出供第三方验证。
class KeyService {
  KeyService([this._kv = const FlutterSecureKV()]);

  static const String seedKey = 'simple_guard.seed.v1';
  final SecureKV _kv;
  Uint8List? _cached;

  Future<Uint8List> ensureKey() async {
    if (_cached != null) return _cached!;
    final existing = await _kv.read(seedKey);
    if (existing != null && existing.isNotEmpty) {
      _cached = base64Decode(existing);
      return _cached!;
    }
    final kp = generateKeyPair();
    await _kv.write(seedKey, kp.seedB64);
    _cached = kp.seed;
    return _cached!;
  }

  Future<Uint8List> publicKey() async =>
      keyPairFromSeed(await ensureKey()).publicKey;

  Future<String> publicKeyB64() async => base64Encode(await publicKey());

  /// 重置密钥（会生成新密钥；旧公钥验证旧视频仍有效）。
  Future<void> reset() async {
    await _kv.delete(seedKey);
    _cached = null;
  }
}
