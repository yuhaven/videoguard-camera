#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simple_guard.py — 极简非对称签名防篡改算法（SimpleGuard）

算法就三步:
  ① H = SHA-256(视频文件全部字节)        对整个文件求一次哈希
  ② S = 私钥签名(H)                      非对称签名（私钥签、公钥验）
  ③ 验证: 重算 H'，比对 H，公钥验签 S     任何 1 字节改动 → H' ≠ H → 报警

为什么"任何一点改动"都必然检出:
  - SHA-256 抗碰撞: 两个不同的文件内容不可能算出相同哈希
  - Ed25519 签名: 没有私钥的人无法为改动后的文件伪造合法签名
  - 加水印/改色/遮挡/插入/拼接/换音轨/重编码 —— 一切修改最终都是字节变化 → 全部检出

命令:
  genkey  --dir D                生成 Ed25519 密钥对
  sign    <视频> <输出.sgd>        签名打包（视频字节原样存入，可 extract 播放）
  verify  <文件.sgd>              验证容器，任何改动立即报警
  check   <文件> --sigfile S      用 S 中记录的哈希+签名验证任意副本
  extract <文件.sgd> --out F      取出原始视频

退出码: 0 = 完全一致; 1 = 检出改动/伪造; 2 = 使用或格式错误
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MAGIC = b"SGD1"

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------- 基础

def sha256_file(path: Path, offset: int = 0) -> str:
    """流式计算文件（从 offset 起）的 SHA-256。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        f.seek(offset)
        while chunk := f.read(4 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def load_priv(path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def load_pub(path):
    return serialization.load_pem_public_key(Path(path).read_bytes())


def pub_raw(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def read_container(path: Path):
    """解析 .sgd 容器，返回 (header, 视频数据起始偏移)。"""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("不是 SimpleGuard 容器（magic 不符）")
        hlen = int.from_bytes(f.read(4), "big")
        header = json.loads(f.read(hlen).decode("utf-8"))
    return header, 8 + hlen


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
    print(f"✓ 密钥对已生成: {d / 'identity.key'}（私钥，离线保管）")
    print(f"                 {d / 'identity.pub'}（公钥，可公开）")
    return 0


def cmd_sign(args) -> int:
    video = Path(args.input)
    priv = load_priv(args.privkey)
    h = sha256_file(video)                       # ① 对整个文件求哈希
    sig = priv.sign(bytes.fromhex(h))            # ② 私钥签名（非对称）
    header = {
        "format": "simple-guard/1",
        "algorithm": "ed25519",
        "sha256": h,
        "signature": b64e(sig),
        "pubkey": b64e(pub_raw(priv.public_key())),
        "size": video.stat().st_size,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    hj = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with open(args.output, "wb") as out, open(video, "rb") as vf:
        out.write(MAGIC)
        out.write(len(hj).to_bytes(4, "big"))
        out.write(hj)
        while chunk := vf.read(4 * 1024 * 1024):
            out.write(chunk)                     # 视频字节一字不动
    print(f"✓ 已签名打包: {args.output}")
    print(f"  文件哈希(SHA-256): {h}")
    print(f"  视频字节原样保存在容器尾部，可用 extract 取出播放")
    return 0


def _get_pub(header: dict, pubkey_file):
    if pubkey_file:
        return load_pub(pubkey_file)
    return Ed25519PublicKey.from_public_bytes(b64d(header["pubkey"]))


def cmd_verify(args) -> int:
    path = Path(args.input)
    try:
        header, off = read_container(path)
    except Exception as e:
        print(f"✗ 检出异常: {e}（容器被破坏或不是有效签名包）")
        return 1
    h = sha256_file(path, off)                   # ③ 重算哈希
    if h != header["sha256"]:
        print("✗ 检出改动: 文件哈希与原始签名不符（哪怕只改 1 个字节也会报警）")
        print(f"  原始 SHA-256: {header['sha256']}")
        print(f"  当前 SHA-256: {h}")
        return 1
    try:
        _get_pub(header, args.pubkey).verify(b64d(header["signature"]),
                                             bytes.fromhex(header["sha256"]))
        print("✓ 完全一致: 文件未有任何改动，签名有效")
        return 0
    except InvalidSignature:
        print("✗ 签名无效: 哈希对得上但签名不合法（伪造签名 / 掉包）")
        return 1


def cmd_check(args) -> int:
    """用 .sgd 中记录的哈希+签名验证任意一个视频文件副本。"""
    try:
        header, _ = read_container(Path(args.sigfile))
    except Exception as e:
        print(f"✗ 签名包异常: {e}")
        return 2
    h = sha256_file(Path(args.input))
    if h != header["sha256"]:
        print("✗ 检出改动: 该文件与原版视频不一致（加水印/改色/遮挡/插入/拼接/换音轨/重编码都会触发）")
        print(f"  原版 SHA-256: {header['sha256']}")
        print(f"  当前 SHA-256: {h}")
        return 1
    try:
        _get_pub(header, args.pubkey).verify(b64d(header["signature"]),
                                             bytes.fromhex(header["sha256"]))
        print("✓ 完全一致: 该文件与原版视频一字不差，签名有效")
        return 0
    except InvalidSignature:
        print("✗ 签名无效: 该文件与原版同哈希但签名不合法（伪造 / 掉包）")
        return 1


def cmd_extract(args) -> int:
    header, off = read_container(Path(args.input))
    with open(args.input, "rb") as f, open(args.out, "wb") as o:
        f.seek(off)
        while chunk := f.read(4 * 1024 * 1024):
            o.write(chunk)
    print(f"✓ 已取出原始视频: {args.out}（{header['size']} 字节，可直接播放）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="极简非对称签名防篡改（SimpleGuard）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("genkey", help="生成 Ed25519 密钥对")
    p.add_argument("--dir", default=".")
    p.set_defaults(func=cmd_genkey)

    p = sub.add_parser("sign", help="对视频整体哈希并私钥签名，打包为 .sgd")
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--privkey", required=True, help="签名私钥 PEM")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="验证 .sgd 容器")
    p.add_argument("input")
    p.add_argument("--pubkey", help="公钥 PEM；省略则用容器内嵌公钥")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("check", help="用 .sgd 中的哈希+签名验证任意视频副本")
    p.add_argument("input")
    p.add_argument("--sigfile", required=True, help="原始 .sgd 签名包")
    p.add_argument("--pubkey", help="公钥 PEM；省略则用容器内嵌公钥")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("extract", help="从 .sgd 取出原始视频")
    p.add_argument("input")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_extract)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
