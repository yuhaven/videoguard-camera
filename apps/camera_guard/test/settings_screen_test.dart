import 'package:camera_guard/main.dart';
import 'package:camera_guard/services/key_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

/// 页面冒烟测试（不依赖相机/平台插件）。
void main() {
  testWidgets('设置页渲染公钥与算法说明（注入内存密钥）', (tester) async {
    final keys = KeyService(MemoryKV());
    await keys.ensureKey();
    await tester.pumpWidget(MaterialApp(
      home: CameraGuardApp(keyService: keys),
    ));
    // 进入设置页
    await tester.tap(find.byTooltip('设置'));
    await tester.pumpAndSettle();
    expect(find.text('验证公钥（可公开，供他人验证你拍摄的内容）'), findsOneWidget);
    expect(find.text('重置密钥'), findsOneWidget);
    // 算法说明在列表下方，滚动后可见
    await tester.scrollUntilVisible(find.textContaining('SimpleGuard'), 200,
        scrollable: find.byType(Scrollable).first);
    expect(find.textContaining('SimpleGuard'), findsOneWidget);
  });
}
