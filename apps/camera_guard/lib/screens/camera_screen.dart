import 'package:camera/camera.dart';
import 'package:flutter/material.dart';

import '../services/key_service.dart';
import 'gallery_screen.dart';
import 'result_screen.dart';
import 'settings_screen.dart';
import 'verify_screen.dart';

/// 相机页：录视频 / 拍照；拍摄完成后自动进入"即签"流程。
class CameraScreen extends StatefulWidget {
  const CameraScreen({super.key, this.keyService});

  final KeyService? keyService;

  @override
  State<CameraScreen> createState() => _CameraScreenState();
}

class _CameraScreenState extends State<CameraScreen> {
  CameraController? _controller;
  String? _error;
  bool _recording = false;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    try {
      final cams = await availableCameras();
      if (cams.isEmpty) throw StateError('未找到相机');
      final c = CameraController(
        cams.first,
        ResolutionPreset.high,
        enableAudio: true,
      );
      await c.initialize();
      if (!mounted) return;
      setState(() => _controller = c);
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = '相机初始化失败: $e\n请授予相机与麦克风权限后重试');
    }
  }

  Future<void> _toggleRecording() async {
    final c = _controller;
    if (c == null || !c.value.isInitialized || _busy) return;
    setState(() => _busy = true);
    try {
      if (!_recording) {
        await c.startVideoRecording();
        if (mounted) setState(() => _recording = true);
      } else {
        final file = await c.stopVideoRecording();
        if (!mounted) return;
        setState(() => _recording = false);
        await Navigator.of(context).push(MaterialPageRoute(
          builder: (_) => ResultScreen(
            mediaPath: file.path,
            isVideo: true,
            keyService: widget.keyService,
          ),
        ));
      }
    } catch (e) {
      if (mounted) {
        setState(() => _error = '录制失败: $e');
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _takePhoto() async {
    final c = _controller;
    if (c == null || !c.value.isInitialized || _busy || _recording) return;
    setState(() => _busy = true);
    try {
      final file = await c.takePicture();
      if (!mounted) return;
      await Navigator.of(context).push(MaterialPageRoute(
        builder: (_) => ResultScreen(
          mediaPath: file.path,
          isVideo: false,
          knownDigest: null,
          keyService: widget.keyService,
        ),
      ));
    } catch (e) {
      if (mounted) setState(() => _error = '拍照失败: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  void dispose() {
    _controller?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black,
        foregroundColor: Colors.white,
        title: const Text('防篡改相机'),
        actions: [
          IconButton(
            tooltip: '验证',
            icon: const Icon(Icons.fact_check_outlined),
            onPressed: () => Navigator.of(context).push(MaterialPageRoute(
                builder: (_) => const VerifyScreen())),
          ),
          IconButton(
            tooltip: '已签名产物',
            icon: const Icon(Icons.folder_outlined),
            onPressed: () => Navigator.of(context).push(MaterialPageRoute(
                builder: (_) => const GalleryScreen())),
          ),
          IconButton(
            tooltip: '设置',
            icon: const Icon(Icons.settings_outlined),
            onPressed: () => Navigator.of(context).push(MaterialPageRoute(
                builder: (_) => SettingsScreen(keyService: widget.keyService))),
          ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_error != null) {
      return Center(
          child: Padding(
        padding: const EdgeInsets.all(24),
        child: Text(_error!,
            style: const TextStyle(color: Colors.white70),
            textAlign: TextAlign.center),
      ));
    }
    final c = _controller;
    if (c == null || !c.value.isInitialized) {
      return const Center(child: CircularProgressIndicator());
    }
    return Column(
      children: [
        Expanded(child: Center(child: CameraPreview(c))),
        Container(
          padding: const EdgeInsets.symmetric(vertical: 24),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: [
              _roundButton(
                icon: Icons.photo_camera_outlined,
                label: '拍照',
                onTap: _busy ? null : _takePhoto,
              ),
              _recordButton(),
              _roundButton(
                icon: Icons.info_outline,
                label: '拍完即签',
                onTap: null,
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _recordButton() {
    final c = _controller;
    return GestureDetector(
      onTap: (c == null || _busy) ? null : _toggleRecording,
      child: Container(
        width: 84,
        height: 84,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          border: Border.all(color: Colors.white, width: 4),
          color: _recording ? Colors.redAccent : Colors.transparent,
        ),
        child: Icon(
          _recording ? Icons.stop : Icons.videocam,
          color: Colors.white,
          size: 36,
        ),
      ),
    );
  }

  Widget _roundButton({
    required IconData icon,
    required String label,
    required VoidCallback? onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, color: Colors.white70, size: 32),
          const SizedBox(height: 4),
          Text(label,
              style: const TextStyle(color: Colors.white54, fontSize: 12)),
        ],
      ),
    );
  }
}
