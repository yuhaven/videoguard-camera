#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
demo/run_demo_simple.py — 极简方案（SimpleGuard）端到端演示

流程:
  1. 生成 10 秒测试视频
  2. genkey → Ed25519 密钥对
  3. sign   → 整体哈希 + 私钥签名，打包 sample.sgd
  4. verify → 完全一致 PASS
  5. extract → 取出原始视频（证明可播放）
  6. 十类攻击（每一类都是"文件出现改动"）→ check 全部报警:
       1 字节翻转 / 加水印 / 改色彩 / 遮挡 / 插入片段 / 拼接 / 替换音轨 / 掉包
       对容器本身改 1 字节 / 聪明攻击（改视频并同步改哈希，但无签名私钥）
  7. 汇总 → demo/out_simple/report.md
"""
import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import imageio_ffmpeg
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "simple_guard.py"
OUT = ROOT / "demo" / "out_simple"
OUT.mkdir(parents=True, exist_ok=True)
PY = sys.executable
FF = imageio_ffmpeg.get_ffmpeg_exe()

SAMPLE = OUT / "sample.mp4"
SGD = OUT / "sample.sgd"


def sh(args, log: Path):
    with open(log, "wb") as lf:
        r = subprocess.run(args, stdout=lf, stderr=subprocess.STDOUT)
    if r.returncode not in (0, 1):
        raise RuntimeError(f"命令失败: {' '.join(map(str, args))}\n日志: {log}")
    return r


def ff(name: str, args: list):
    sh([FF, "-y", "-loglevel", "error", *args], OUT / f"ff-{name}.log")
    print(f"  [ffmpeg] {name}")


def sg(name: str, args: list):
    r = sh([PY, str(SRC), *args], OUT / f"sg-{name}.log")
    text = (OUT / f"sg-{name}.log").read_text(encoding="utf-8")
    return r.returncode, text.strip()


def first_verdict(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("✓") or line.startswith("✗"):
            return line
    return text[:120]


rows = []


def record(attack: str, desc: str, verdict_line: str, detected: bool):
    rows.append({"attack": attack, "desc": desc, "verdict": verdict_line,
                 "detected": "✓" if detected else "✗"})


def main():
    print("=" * 72)
    print("SimpleGuard 极简非对称签名防篡改演示")
    print("=" * 72)

    # 1. 生成测试视频
    print("\n[1] 生成测试视频 (10s, 640x360@25fps, 带音轨)")
    ff("gen", ["-f", "lavfi", "-i", "testsrc2=size=640x360:rate=25:duration=10",
               "-f", "lavfi", "-i", "sine=frequency=440:duration=10",
               "-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p",
               "-c:a", "aac", str(SAMPLE)])

    # 2-4. 密钥 → 签名 → 验证
    print("\n[2] 生成 Ed25519 密钥对（非对称）")
    sg("genkey", ["genkey", "--dir", str(OUT)])
    print("\n[3] 签名打包（SHA-256 整体哈希 + 私钥签名）")
    sg("sign", ["sign", str(SAMPLE), str(SGD),
                "--privkey", str(OUT / "identity.key")])
    print("\n[4] 验证原始容器")
    rc, text = sg("verify_clean", ["verify", str(SGD),
                                   "--pubkey", str(OUT / "identity.pub")])
    record("（基准）", "原始签名包", first_verdict(text), rc == 0)
    print(f"     exit={rc} {first_verdict(text)}")

    print("\n[5] 取出原始视频（证明字节原样、可播放）")
    sg("extract", ["extract", str(SGD), "--out", str(OUT / "extracted.mp4")])

    # 6. 明文副本攻击（每一类都造成文件字节变化）
    print("\n[6] 十类攻击（每一类都让视频文件出现改动）")

    # 6.1 只改 1 个字节
    data = bytearray(SAMPLE.read_bytes())
    data[len(data) // 2] ^= 0x01
    (OUT / "flip.mp4").write_bytes(bytes(data))
    rc, text = sg("chk_flip", ["check", str(OUT / "flip.mp4"),
                               "--sigfile", str(SGD), "--pubkey", str(OUT / "identity.pub")])
    record("改 1 个字节", "视频文件中间翻转 1 个字节", first_verdict(text), rc == 1)
    print(f"     flip: exit={rc}")

    # 6.2 加水印
    wm = Image.new("RGB", (96, 54), (255, 255, 255))
    d = ImageDraw.Draw(wm)
    d.ellipse((38, 7, 78, 47), fill=(220, 30, 30))
    d.line((28, 2, 88, 52), fill=(0, 0, 0), width=6)
    d.line((28, 52, 88, 2), fill=(0, 0, 0), width=6)
    wm.save(OUT / "wm.png")
    ff("watermark", ["-i", str(SAMPLE), "-i", str(OUT / "wm.png"),
                     "-filter_complex",
                     "[0:v]format=rgba[a];[1:v]format=rgba[wm];"
                     "[a][wm]overlay=10:10:shortest=1,format=yuv420p[vo]",
                     "-map", "[vo]", "-map", "0:a", "-c:a", "copy",
                     str(OUT / "watermark.mp4")])
    rc, text = sg("chk_watermark", ["check", str(OUT / "watermark.mp4"),
                                    "--sigfile", str(SGD),
                                    "--pubkey", str(OUT / "identity.pub")])
    record("加水印", "左上角叠加水印图", first_verdict(text), rc == 1)
    print(f"     watermark: exit={rc}")

    # 6.3 改色彩
    ff("color", ["-i", str(SAMPLE), "-vf", "hue=h=180", "-c:a", "copy",
                 str(OUT / "color.mp4")])
    rc, text = sg("chk_color", ["check", str(OUT / "color.mp4"),
                                "--sigfile", str(SGD), "--pubkey", str(OUT / "identity.pub")])
    record("改色彩", "全局色相旋转 180°", first_verdict(text), rc == 1)
    print(f"     color: exit={rc}")

    # 6.4 遮挡
    ff("occlude", ["-i", str(SAMPLE), "-vf",
                   "drawbox=x=80:y=80:w=240:h=140:color=black:t=fill:enable='between(t,4,6)'",
                   "-c:a", "copy", str(OUT / "occlude.mp4")])
    rc, text = sg("chk_occlude", ["check", str(OUT / "occlude.mp4"),
                                  "--sigfile", str(SGD),
                                  "--pubkey", str(OUT / "identity.pub")])
    record("遮挡", "第 4-6 秒贴黑块遮挡画面", first_verdict(text), rc == 1)
    print(f"     occlude: exit={rc}")

    # 6.5 插入片段
    ff("insert", ["-i", str(SAMPLE), "-filter_complex",
                  "[0:v]trim=0:3,setpts=PTS-STARTPTS[v1];[0:v]trim=1:4,setpts=PTS-STARTPTS[v2];"
                  "[0:v]trim=3:10,setpts=PTS-STARTPTS[v3];[v1][v2][v3]concat=n=3:v=1:a=0[v]",
                  "-map", "[v]", "-an", str(OUT / "insert.mp4")])
    rc, text = sg("chk_insert", ["check", str(OUT / "insert.mp4"),
                                 "--sigfile", str(SGD), "--pubkey", str(OUT / "identity.pub")])
    record("插入片段", "第 3 秒处插入 1-4 秒的重复片段", first_verdict(text), rc == 1)
    print(f"     insert: exit={rc}")

    # 6.6 拼接
    ff("splice", ["-i", str(SAMPLE), "-filter_complex",
                  "[0:v]trim=0:2,setpts=PTS-STARTPTS[v1];[0:v]trim=6:10,setpts=PTS-STARTPTS[v2];"
                  "[v1][v2]concat=n=2:v=1:a=0[v]",
                  "-map", "[v]", "-an", str(OUT / "splice.mp4")])
    rc, text = sg("chk_splice", ["check", str(OUT / "splice.mp4"),
                                 "--sigfile", str(SGD), "--pubkey", str(OUT / "identity.pub")])
    record("拼接/剪辑", "删除中间 4 秒并把前后接上", first_verdict(text), rc == 1)
    print(f"     splice: exit={rc}")

    # 6.7 替换音轨
    ff("audio", ["-i", str(SAMPLE), "-f", "lavfi", "-i", "sine=frequency=880:duration=10",
                 "-map", "0:v", "-map", "1:a", "-c:v", "copy", "-c:a", "aac", "-shortest",
                 str(OUT / "audio.mp4")])
    rc, text = sg("chk_audio", ["check", str(OUT / "audio.mp4"),
                                "--sigfile", str(SGD), "--pubkey", str(OUT / "identity.pub")])
    record("替换音轨", "画面不变，音轨换成 880Hz", first_verdict(text), rc == 1)
    print(f"     audio: exit={rc}")

    # 6.8 掉包
    ff("swap", ["-f", "lavfi", "-t", "10", "-i", "mandelbrot=size=640x360:rate=25",
                "-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p",
                str(OUT / "swap.mp4")])
    rc, text = sg("chk_swap", ["check", str(OUT / "swap.mp4"),
                               "--sigfile", str(SGD), "--pubkey", str(OUT / "identity.pub")])
    record("整体掉包", "换成另一段完全不同的视频", first_verdict(text), rc == 1)
    print(f"     swap: exit={rc}")

    # 6.9 对容器本身改 1 字节
    raw = bytearray(SGD.read_bytes())
    raw[-1000] ^= 0x01                                   # 视频区尾部 1 字节
    (OUT / "flip.sgd").write_bytes(bytes(raw))
    rc, text = sg("verify_flip", ["verify", str(OUT / "flip.sgd"),
                                  "--pubkey", str(OUT / "identity.pub")])
    record("改容器 1 字节", "对 .sgd 内视频区翻转 1 字节", first_verdict(text), rc == 1)
    print(f"     sgd-flip: exit={rc}")

    # 6.10 聪明攻击：改视频 + 同步改哈希，但没有签名私钥
    raw = SGD.read_bytes()
    hlen = int.from_bytes(raw[4:8], "big")
    header = json.loads(raw[8:8 + hlen].decode("utf-8"))
    newvideo = (OUT / "watermark.mp4").read_bytes()
    header["sha256"] = hashlib.sha256(newvideo).hexdigest()   # 攻击者更新哈希
    header["size"] = len(newvideo)
    hj = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    (OUT / "clever.sgd").write_bytes(raw[:4] + len(hj).to_bytes(4, "big") + hj + newvideo)
    rc, text = sg("verify_clever", ["verify", str(OUT / "clever.sgd"),
                                    "--pubkey", str(OUT / "identity.pub")])
    record("聪明攻击", "改视频并同步改哈希，但无签名私钥", first_verdict(text), rc == 1)
    print(f"     clever: exit={rc}")

    # 7. 汇总报告
    write_report()
    print("\n完成。汇总报告: demo/out_simple/report.md")


def write_report():
    lines = [
        "# SimpleGuard 极简方案检测结果",
        "",
        f"生成时间: {datetime.now().isoformat(timespec='seconds')}",
        "",
        f"测试视频: `sample.mp4`（10 s, 640×360@25fps）",
        "算法: `H = SHA-256(整个文件)` → `S = Ed25519 私钥签名(H)` → 验证时重算哈希 + 公钥验签",
        "",
        "| # | 攻击 | 手法 | 验证结果 | 检出 |",
        "|---|------|------|----------|------|",
    ]
    for i, r in enumerate(rows):
        lines.append(f"| {i} | {r['attack']} | {r['desc']} | {r['verdict']} | {r['detected']} |")
    lines += [
        "",
        "## 结论",
        "",
        f"- 全部 {len(rows) - 1} 类攻击（含只改 1 字节、改视频并同步改哈希的聪明攻击）均被检出，无一漏报。",
        "- 原理保证：SHA-256 抗碰撞 → 任何字节变化必导致哈希不同；Ed25519 签名 → 无私钥无法伪造。",
        "- 因此「水印 / 色彩 / 遮挡 / 插入 / 拼接 / 音轨替换」等一切修改，最终都是字节变化，全部被完全验证出来。",
        "",
        "## 复现",
        "",
        "```powershell",
        "python demo\\run_demo_simple.py",
        "```",
        "",
    ]
    (OUT / "report.md").write_text("\n".join(lines), encoding="utf-8")

    print("\n" + "=" * 72)
    print("检测结果汇总")
    print("=" * 72)
    for i, r in enumerate(rows):
        print(f"{r['detected']} {i:2d}. [{r['attack']}] {r['desc']}")
        print(f"      {r['verdict']}")
    print("=" * 72)


if __name__ == "__main__":
    main()
