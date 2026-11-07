#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
videoguard.py — 加密视频防篡改工具（算法 PoC）

子命令:
  genkey                         生成 Ed25519 签名密钥对
  protect    <视频> <输出.vgd>     加密 + 分块 Merkle 完整性 + 帧感知哈希清单 + 签名
  verify     <文件.vgd>            解密并全量校验（密文/签名/字节/结构/画面/音频）
  manifest-export <文件.vgd>       导出公开清单（含签名与公钥，可公开分发）
  verify-plain <视频> --manifest M 用公开清单离线校验任意"明文副本"

层次:
  L0 加密:    AES-256-GCM（口令 PBKDF2 派生 KEK，封装随机内容密钥 CK）
  L1 文件级:  1 MiB 分块 SHA-256 + Merkle 树 + Ed25519 签名 → 定位字节篡改
  L2 结构级:  时长/帧率/分辨率/总帧数/采样序列
  L3 画面级:  逐秒采样帧 pHash/dHash（汉明距离）→ 定位画面篡改到秒
  L4 音频级:  16 kHz 单声道 PCM 每秒分片哈希

退出码: 0=PASS  1=检出篡改/异常  2=加解密或格式错误
口令: --passphrase 或环境变量 VG_PASS
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import imageio_ffmpeg
import numpy as np
from PIL import Image
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()

# Windows 控制台/重定向默认 GBK，统一用 UTF-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

MAGIC = b"VGD1"
BLOCK_SIZE = 1024 * 1024          # 1 MiB 分块
KDF_ITERS = 600_000               # KEK 派生迭代次数
SIGN_KDF_ITERS = 200_000          # 降级 HMAC 模式签名密钥迭代次数
AUDIO_RATE = 16000                # 音频指纹: 16 kHz 单声道
AUDIO_CHUNK = 32000               # 32000 字节 = 1 s @ 16 kHz s16le
FRAME_INTERVAL = 1.0              # 采样帧间隔（秒）
PHASH_TAMPER = 20                 # 汉明距离 > 20 → 判定画面被修改
PHASH_SUSPECT = 10                # 汉明距离 > 10 → 疑似轻处理
GCM_NONCE_WRAP = b"\x00" * 12     # 封装 KEK 的固定 nonce（KEK 每文件唯一）


# ---------------------------------------------------------------- 基础工具

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(4 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def canonical(obj) -> str:
    """规范化 JSON 序列化（键排序、无空格）→ 签名的稳定字节表示。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def pbkdf2(passphrase: str, salt: bytes, iters: int, dklen: int = 32) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=dklen, salt=salt, iterations=iters)
    return kdf.derive(passphrase.encode("utf-8"))


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


# ---------------------------------------------------------------- Merkle 树

def merkle_root(leaf_hexes: list) -> str:
    """由叶哈希列表构建 Merkle 根（奇数层复制末叶补偶）。"""
    if not leaf_hexes:
        return sha256_hex(b"")
    level = [bytes.fromhex(h) for h in leaf_hexes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def file_block_hashes(path: Path) -> list:
    leaves = []
    with open(path, "rb") as f:
        while chunk := f.read(BLOCK_SIZE):
            leaves.append(sha256_hex(chunk))
    return leaves


# ---------------------------------------------------------------- ffmpeg

def run_ff(args: list, errfile: Path, check: bool = True) -> subprocess.CompletedProcess:
    with open(errfile, "wb") as ef:
        r = subprocess.run([FFMPEG] + args, stdout=subprocess.DEVNULL, stderr=ef)
    if check and r.returncode != 0:
        raise RuntimeError("ffmpeg 失败: " + " ".join(map(str, args)))
    return r


def probe_video(path: Path) -> dict:
    """用 ffmpeg 探测时长/分辨率/fps/帧数/音轨。"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tf:
        err = Path(tf.name)
    try:
        run_ff(["-hide_banner", "-i", str(path)], err, check=False)
        text = err.read_text(errors="replace")
    finally:
        try:
            err.unlink()
        except OSError:
            pass
    info: dict = {"duration": None, "width": None, "height": None, "fps": None,
                  "frame_count": None, "has_audio": False}
    m = re.search(r"Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)", text)
    if m:
        info["duration"] = int(m.group(1)) * 3600 + int(m.group(2)) * 60 + float(m.group(3))
    mv = re.search(r"Video:.*?(\d{2,5})x(\d{2,5})", text, re.S)
    if mv:
        info["width"], info["height"] = int(mv.group(1)), int(mv.group(2))
    mf = re.search(r"([\d.]+)\s*fps", text)
    if mf:
        info["fps"] = float(mf.group(1))
    info["has_audio"] = "Audio:" in text
    if info["duration"] is not None and info["fps"]:
        info["frame_count"] = int(round(info["duration"] * info["fps"]))
    return info


def extract_sample_frames(video: Path, outdir: Path) -> list:
    """每 FRAME_INTERVAL 秒抽取 1 帧（时间戳对齐采样）。"""
    outdir.mkdir(parents=True, exist_ok=True)
    run_ff(["-loglevel", "error", "-i", str(video), "-vf", f"fps=1/{int(FRAME_INTERVAL)}",
            "-fps_mode", "vfr", "-f", "image2", str(outdir / "f%04d.png")],
           outdir / "ff-extract.log")
    return sorted(outdir.glob("f*.png"))


def extract_audio_chunks(video: Path, outdir: Path):
    """解码为 16 kHz 单声道 s16le PCM，按 1 s 分片哈希。无音轨返回 None。"""
    outdir.mkdir(parents=True, exist_ok=True)
    pcm = outdir / "audio.pcm"
    run_ff(["-loglevel", "error", "-i", str(video), "-map", "0:a:0",
            "-f", "s16le", "-ac", "1", "-ar", str(AUDIO_RATE), str(pcm)],
           outdir / "ff-audio.log", check=False)
    if not pcm.exists():
        return None
    data = pcm.read_bytes()
    if not data:
        return None
    return [sha256_hex(data[i:i + AUDIO_CHUNK]) for i in range(0, len(data), AUDIO_CHUNK)]


# ---------------------------------------------------------------- 感知哈希

def phash_dhash(png: Path):
    """返回 (pHash, dHash) 两个 64 bit 整数。"""
    img = Image.open(png).convert("L").resize((32, 32), Image.Resampling.LANCZOS)
    a = np.asarray(img, dtype=np.float64)
    n = np.arange(32)
    c = np.cos(np.pi / 32.0 * (n[:, None] * (n[None, :] + 0.5)))
    c[0, :] /= np.sqrt(2.0)                      # 正交 DCT-II 基
    d = c @ a @ c.T
    low = d[:8, :8]                              # 左上 8×8 低频系数
    med = float(np.median(low))
    ph = int("".join("1" if float(v) > med else "0" for v in low.flat), 2)

    img2 = Image.open(png).convert("L").resize((9, 8), Image.Resampling.LANCZOS)
    b = np.asarray(img2, dtype=np.uint8)
    bits = (b[:, 1:] > b[:, :-1]).reshape(-1)    # 横向梯度差分
    dh = int("".join("1" if bool(x) else "0" for x in bits), 2)
    return ph, dh


# ---------------------------------------------------------------- 签名

def verify_signature(manifest: dict, passphrase: str, pubkey_file=None) -> bool:
    signer = manifest.get("signer", "")
    if "signature" not in manifest:
        return False
    m2 = {k: v for k, v in manifest.items() if k != "signature"}
    digest_b = hashlib.sha256(canonical(m2).encode("utf-8")).digest()
    sig = b64d(manifest["signature"])
    if signer.startswith("ed25519:"):
        if pubkey_file:
            pub = serialization.load_pem_public_key(Path(pubkey_file).read_bytes())
            raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        else:
            raw = b64d(signer.split(":", 1)[1])              # 用清单内嵌公钥
        try:
            Ed25519PublicKey.from_public_bytes(raw).verify(sig, digest_b)
            return True
        except InvalidSignature:
            return False
    key = pbkdf2(passphrase, b64d(manifest.get("sign_salt", b64e(b"0"))), SIGN_KDF_ITERS)
    return hmac.compare_digest(hmac.new(key, digest_b, hashlib.sha256).digest(), sig)


# ---------------------------------------------------------------- 清单构建

def build_manifest(video: Path, privkey, passphrase: str, sign_salt: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="vg-protect-") as td:
        tdir = Path(td)
        probe = probe_video(video)
        pngs = extract_sample_frames(video, tdir / "frames")
        samples = []
        for i, p in enumerate(pngs):
            ph, dh = phash_dhash(p)
            samples.append({"i": i, "t": round(i * FRAME_INTERVAL, 3),
                            "phash": f"{ph:016x}", "dhash": f"{dh:016x}"})
        audio_chunks = extract_audio_chunks(video, tdir / "audio")
        leaves = file_block_hashes(video)

    manifest = {
        "format": "videoguard-manifest/1",
        "file": {
            "name": video.name,
            "size": video.stat().st_size,
            "sha256": sha256_file(video),
            "duration": round(probe["duration"], 3) if probe["duration"] is not None else None,
            "width": probe["width"], "height": probe["height"], "fps": probe["fps"],
            "frame_count": probe["frame_count"], "has_audio": probe["has_audio"],
        },
        "blocks": {"size": BLOCK_SIZE, "count": len(leaves),
                   "leaves": leaves, "merkle_root": merkle_root(leaves)},
        "frames": {"sample_interval_sec": FRAME_INTERVAL, "count": len(samples),
                   "samples": samples},
        "audio": ({"sample_rate": AUDIO_RATE, "chunk_sec": 1.0,
                   "count": len(audio_chunks), "chunks": audio_chunks}
                  if audio_chunks is not None else None),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sign_salt": b64e(sign_salt),
    }
    # 先写 signer，再对含 signer 的清单摘要签名（signature 不参与摘要）
    if privkey is not None:
        pub_raw = privkey.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        manifest["signer"] = "ed25519:" + b64e(pub_raw)
    else:
        manifest["signer"] = "hmac-sha256"
    digest_b = hashlib.sha256(canonical(manifest).encode("utf-8")).digest()
    if privkey is not None:
        manifest["signature"] = b64e(privkey.sign(digest_b))
    else:
        key = pbkdf2(passphrase, sign_salt, SIGN_KDF_ITERS)
        manifest["signature"] = b64e(hmac.new(key, digest_b, hashlib.sha256).digest())
    return manifest


# ---------------------------------------------------------------- protect

def cmd_protect(args) -> int:
    video = Path(args.input)
    output = Path(args.output)
    passphrase = args.passphrase or os.environ.get("VG_PASS")
    if not passphrase:
        print("错误: 需要口令（--passphrase 或环境变量 VG_PASS）", file=sys.stderr)
        return 2
    privkey = None
    if args.privkey:
        privkey = serialization.load_pem_private_key(
            Path(args.privkey).read_bytes(), password=None)

    salt = os.urandom(16)
    sign_salt = os.urandom(16)
    ck = os.urandom(32)
    manifest = build_manifest(video, privkey, passphrase, sign_salt)
    manifest_bytes = canonical(manifest).encode("utf-8")
    payload_len = len(manifest_bytes) + video.stat().st_size

    kek = pbkdf2(passphrase, salt, KDF_ITERS)
    nonce = os.urandom(12)
    wrapped = AESGCM(kek).encrypt(GCM_NONCE_WRAP, ck, None)

    header = {
        "format": "videoguard/1", "cipher": "aes-256-gcm",
        "kdf": "pbkdf2-hmac-sha256", "kdf_iters": KDF_ITERS,
        "salt": b64e(salt), "wrapped_key": b64e(wrapped), "nonce": b64e(nonce),
        "manifest_len": len(manifest_bytes), "payload_len": payload_len,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    hj = canonical(header).encode("utf-8")

    enc = Cipher(algorithms.AES(ck), modes.GCM(nonce)).encryptor()
    with open(output, "wb") as out, open(video, "rb") as vf:
        out.write(MAGIC)
        out.write(len(hj).to_bytes(4, "big"))
        out.write(hj)
        out.write(enc.update(manifest_bytes))
        while chunk := vf.read(4 * 1024 * 1024):
            out.write(enc.update(chunk))
        out.write(enc.finalize())   # 冲掉残留缓冲（GCM 模式返回空）
        out.write(enc.tag)          # 16 字节 GCM 认证标签

    print(f"✓ 已加密保护: {output}")
    print(f"  源文件      : {video.name} ({video.stat().st_size} 字节)")
    print(f"  块哈希      : {manifest['blocks']['count']} 块 × {BLOCK_SIZE // 1024} KiB")
    print(f"  Merkle 根   : {manifest['blocks']['merkle_root']}")
    print(f"  采样帧      : {manifest['frames']['count']} 帧 (每 {FRAME_INTERVAL}s)")
    print(f"  音频分片    : {manifest['audio']['count'] if manifest['audio'] else 0}")
    print(f"  签名        : {manifest['signer']}")
    return 0


# ---------------------------------------------------------------- 解密

def decrypt_vgd(path: Path, passphrase: str, outdir: Path):
    """返回 (header, manifest, 解密后的视频路径)。密文被改/口令错误抛异常。"""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("不是 VideoGuard 容器（magic 不符）")
        hlen = int.from_bytes(f.read(4), "big")
        header = json.loads(f.read(hlen).decode("utf-8"))
        kek = pbkdf2(passphrase, b64d(header["salt"]), int(header["kdf_iters"]))
        ck = AESGCM(kek).decrypt(GCM_NONCE_WRAP, b64d(header["wrapped_key"]), None)
        payload = f.read(int(header["payload_len"]))
        tag = f.read(16)
        dec = Cipher(algorithms.AES(ck), modes.GCM(b64d(header["nonce"]), tag)).decryptor()
        plain = dec.update(payload) + dec.finalize()   # InvalidTag → 密文被篡改
    mlen = int(header["manifest_len"])
    manifest = json.loads(plain[:mlen].decode("utf-8"))
    name = re.sub(r"[^A-Za-z0-9._-]", "_", manifest["file"]["name"])
    vpath = Path(outdir) / name
    vpath.write_bytes(plain[mlen:])
    return header, manifest, vpath


# ---------------------------------------------------------------- 全量校验

def check_all(video: Path, manifest: dict, passphrase: str, pubkey_file=None) -> dict:
    """对（明文）视频执行 L1–L4 校验，返回结构化报告。"""
    rep = {"file": manifest["file"]["name"], "signature_ok": None,
           "verdict": "", "notes": []}
    notes = rep["notes"]

    # ---- 签名（掉包/伪造判定，最高优先级）----
    rep["signature_ok"] = verify_signature(manifest, passphrase, pubkey_file)
    if not rep["signature_ok"]:
        notes.append("签名验证失败：文件不是原始发布者签发的（掉包或伪造重签）")

    # ---- L1 字节级 ----
    mf, mb = manifest["file"], manifest["blocks"]
    size = video.stat().st_size
    whole = sha256_file(video)
    leaves = file_block_hashes(video)
    bytes_identical = (size == mf["size"] and whole == mf["sha256"]
                       and leaves == mb["leaves"])
    block_ranges = []
    if not bytes_identical:
        n = min(len(leaves), len(mb["leaves"]))
        start = None
        for i in range(n):
            if leaves[i] != mb["leaves"][i]:
                if start is None:
                    start = i
            elif start is not None:
                block_ranges.append([start + 1, i]); start = None
        if start is not None:
            block_ranges.append([start + 1, n])
        if len(leaves) != len(mb["leaves"]):
            notes.append(f"文件大小/分块数不符: 原始 {mf['size']} 字节/{mb['count']} 块 → 当前 {size} 字节/{len(leaves)} 块（存在删除或插入）")
        if block_ranges:
            shown = ", ".join(f"{a}-{b}" for a, b in block_ranges[:10])
            notes.append(f"字节级改动块区间: {shown}" + ("..." if len(block_ranges) > 10 else ""))
        elif len(leaves) == len(mb["leaves"]):
            notes.append("整文件重写（全部块哈希改变，典型为重新编码/转码或整体替换）")
    else:
        notes.append("文件字节与原件完全一致")
    rep["blocks_differ"] = block_ranges
    rep["bytes_identical"] = bytes_identical

    # ---- L2 结构级 ----
    probe = probe_video(video)
    struct_bad = []
    if mf["duration"] is not None and probe["duration"] is not None:
        if abs(mf["duration"] - probe["duration"]) > 0.3:
            struct_bad.append(f"时长 {mf['duration']}s → {round(probe['duration'], 2)}s")
    if probe["width"] != mf["width"] or probe["height"] != mf["height"]:
        struct_bad.append(f"分辨率 {mf['width']}x{mf['height']} → {probe['width']}x{probe['height']}")
    if mf["fps"] is not None and probe["fps"] is not None and abs(mf["fps"] - probe["fps"]) > 0.15:
        struct_bad.append(f"帧率 {mf['fps']} → {probe['fps']}")
    if mf["frame_count"] is not None and probe["frame_count"] is not None:
        if abs(mf["frame_count"] - probe["frame_count"]) > 3:
            struct_bad.append(f"总帧数 {mf['frame_count']} → {probe['frame_count']}")
    rep["structure_bad"] = bool(struct_bad)
    for s in struct_bad:
        notes.append("结构指纹不符: " + s)

    # ---- L3 画面级 ----
    with tempfile.TemporaryDirectory(prefix="vg-verify-") as td:
        tdir = Path(td)
        pngs = extract_sample_frames(video, tdir / "frames")
        audio_chunks = extract_audio_chunks(video, tdir / "audio")
        mf_samples = manifest["frames"]["samples"]
        tampered, suspect = [], []
        max_ph = max_dh = 0
        if len(pngs) != len(mf_samples):
            notes.append(f"采样帧数不符: 原始 {len(mf_samples)} → 当前 {len(pngs)}（存在删除/插入片段）")
        for i in range(min(len(pngs), len(mf_samples))):
            ph, dh = phash_dhash(pngs[i])
            d_ph = hamming(int(mf_samples[i]["phash"], 16), ph)
            d_dh = hamming(int(mf_samples[i]["dhash"], 16), dh)
            max_ph, max_dh = max(max_ph, d_ph), max(max_dh, d_dh)
            t = mf_samples[i]["t"]
            if d_ph > PHASH_TAMPER or d_dh > PHASH_TAMPER:
                tampered.append({"t": t, "phash_dist": d_ph, "dhash_dist": d_dh})
            elif d_ph > PHASH_SUSPECT or d_dh > PHASH_SUSPECT:
                suspect.append({"t": t, "phash_dist": d_ph, "dhash_dist": d_dh})
        rep["frames"] = {"expected": len(mf_samples), "actual": len(pngs),
                         "tampered": tampered, "suspect": suspect,
                         "max_phash_dist": max_ph, "max_dhash_dist": max_dh}
        if tampered:
            secs = ", ".join(f"{x['t']:.0f}s" for x in tampered[:20])
            notes.append(f"画面被修改的采样点: {secs}"
                         + ("..." if len(tampered) > 20 else ""))
        if suspect:
            secs = ", ".join(f"{x['t']:.0f}s" for x in suspect[:20])
            notes.append(f"疑似轻处理的采样点: {secs}")

        # ---- L4 音频级 ----
        rep["audio_ok"] = None
        audio_removed = False
        if manifest["audio"] is None and audio_chunks is None:
            rep["audio_ok"] = True
        elif manifest["audio"] is None:
            rep["audio_ok"] = True
            notes.append("检测到新增音轨（原件无音轨）")
        elif audio_chunks is None:
            rep["audio_ok"] = False
            audio_removed = True
            notes.append("音轨丢失或被删除")
        else:
            rep["audio_ok"] = (audio_chunks == manifest["audio"]["chunks"])
            if not rep["audio_ok"]:
                notes.append("音频内容与原件不一致（被替换/篡改/重编码）")

    # ---- 判定 ----
    if not rep["signature_ok"]:
        verdict = "SIGNATURE_INVALID"
    elif rep["structure_bad"] or tampered or audio_removed:
        verdict = "TAMPERED"
    elif bytes_identical and rep["audio_ok"] is not False and not suspect:
        verdict = "PASS"
    elif not bytes_identical and not suspect:
        verdict = "REENCODED"
    else:
        verdict = "SUSPECT_LIGHT_PROCESSING"
    rep["verdict"] = verdict
    return rep


def print_report(rep: dict):
    label = {
        "PASS": "✓ 原件一致（未检出任何篡改）",
        "TAMPERED": "✗ 检出篡改",
        "REENCODED": "⚠ 字节级变化但画面内容一致（重编码/转码/元数据修改）",
        "SUSPECT_LIGHT_PROCESSING": "⚠ 疑似轻处理（画面有轻微差异）",
        "SIGNATURE_INVALID": "✗ 签名无效（掉包/伪造）",
        "CIPHERTEXT_TAMPERED": "✗ 密文被篡改（容器损坏）",
    }
    print(f"判定: {label.get(rep['verdict'], rep['verdict'])}")
    for n in rep.get("notes", []):
        print(f"  · {n}")
    fr = rep.get("frames")
    if fr:
        print(f"  · 画面最大差异: pHash {fr['max_phash_dist']} bit / dHash {fr['max_dhash_dist']} bit"
              f"（阈值 {PHASH_TAMPER}）")


# ---------------------------------------------------------------- 命令

def cmd_genkey(args) -> int:
    d = Path(args.dir)
    d.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    (d / "identity.key").write_bytes(priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (d / "identity.pub").write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"✓ 密钥对已生成: {d / 'identity.key'} / {d / 'identity.pub'}")
    print("  私钥务必离线保管，公钥随清单分发。")
    return 0


def cmd_verify(args) -> int:
    passphrase = args.passphrase or os.environ.get("VG_PASS")
    if not passphrase:
        print("错误: 需要口令", file=sys.stderr)
        return 2
    rep = None
    try:
        with tempfile.TemporaryDirectory(prefix="vg-verify-") as td:
            header, manifest, vpath = decrypt_vgd(Path(args.input), passphrase, Path(td))
            rep = check_all(vpath, manifest, passphrase, args.pubkey)
    except Exception as e:
        print(f"✗ 密文层校验失败: {e}")
        print("  判定: CIPHERTEXT_TAMPERED（密文被篡改/口令错误/容器损坏）")
        return 2
    if rep["verdict"] == "PASS":
        print("✓ 密文层 GCM 校验通过，内容完整")
    print_report(rep)
    if args.report_out:
        Path(args.report_out).write_text(json.dumps(rep, ensure_ascii=False, indent=2),
                                         encoding="utf-8")
    return 0 if rep["verdict"] == "PASS" else 1


def cmd_manifest_export(args) -> int:
    passphrase = args.passphrase or os.environ.get("VG_PASS")
    if not passphrase:
        print("错误: 需要口令", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="vg-export-") as td:
        _, manifest, _ = decrypt_vgd(Path(args.input), passphrase, Path(td))
    Path(args.out).write_text(canonical(manifest), encoding="utf-8")
    print(f"✓ 公开清单已导出: {args.out}（含签名与公钥，可安全公开分发）")
    return 0


def cmd_verify_plain(args) -> int:
    passphrase = args.passphrase or os.environ.get("VG_PASS")
    if not passphrase and not args.pubkey:
        print("错误: 需要口令（--passphrase/VG_PASS）或 --pubkey", file=sys.stderr)
        return 2
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    rep = check_all(Path(args.input), manifest, passphrase or "", args.pubkey)
    print_report(rep)
    if args.report_out:
        Path(args.report_out).write_text(json.dumps(rep, ensure_ascii=False, indent=2),
                                         encoding="utf-8")
    return 0 if rep["verdict"] == "PASS" else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="加密视频防篡改工具（PoC）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("genkey", help="生成 Ed25519 签名密钥对")
    p.add_argument("--dir", default=".")
    p.set_defaults(func=cmd_genkey)

    p = sub.add_parser("protect", help="加密并签名视频")
    p.add_argument("input"); p.add_argument("output")
    p.add_argument("--privkey", help="签名私钥 PEM；省略则用 HMAC 降级模式")
    p.add_argument("--passphrase")
    p.set_defaults(func=cmd_protect)

    p = sub.add_parser("verify", help="验证 .vgd 容器")
    p.add_argument("input")
    p.add_argument("--pubkey", help="签名公钥 PEM（HMAC 模式不需要）")
    p.add_argument("--passphrase")
    p.add_argument("--report-out")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("manifest-export", help="导出公开清单")
    p.add_argument("input"); p.add_argument("--out", required=True)
    p.add_argument("--passphrase")
    p.set_defaults(func=cmd_manifest_export)

    p = sub.add_parser("verify-plain", help="用公开清单离线校验明文视频副本")
    p.add_argument("input"); p.add_argument("--manifest", required=True)
    p.add_argument("--pubkey")
    p.add_argument("--passphrase")
    p.add_argument("--report-out")
    p.set_defaults(func=cmd_verify_plain)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
