#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenAppFilter 特征库打包工具。

1. 明文 tar 打包 (free 版): feature.cfg + app_icons/ -> .tar
2. 加密 feature.bin (高级版, v4.0 容器): 明文文本 --XTEA-CTR--> feature.bin
3. 解密 feature.bin -> 明文 (验证/往返测试)

feature.bin 容器格式 (与 open-app-filter/src/fwx_feature.c 完全一致):
    偏移 0   4B  magic    'F' 'W' 'X' 'B'
    偏移 4   1B  格式版本  1
    偏移 5   1B  算法      1 = XTEA-CTR
    偏移 6   2B  头长度    24 (LE16)
    偏移 8   4B  明文长度  plain_len (LE32)
    偏移 12  4B  明文CRC32 (LE32)
    偏移 16  8B  nonce     (LE64, 随机)
    偏移 24  plain_len B  密文

XTEA 参数 (硬编码于 fwx_feature.c):
    key   = {0x8f4c29a1, 0x73b6d502, 0xc14e87f3, 0x2ad95b60}
    delta = 0x9e3779b9, 32 轮, CTR 模式 counter 从 nonce 递增

用法:
    python pack_feature.py tar   <feature.cfg> <out.tar>  [--icons DIR]
    python pack_feature.py bin   <feature.cfg> <out.bin>  [--format v4.0]
    python pack_feature.py decrypt <in.bin> <out.txt>
"""
import argparse
import gzip
import io
import os
import struct
import sys
import tarfile
import zipfile
import zlib

MAGIC = b"FWXB"
FORMAT_VERSION = 1
ALGO_XTEA_CTR = 1
HEADER_SIZE = 24
XTEA_KEY = (0x8F4C29A1, 0x73B6D502, 0xC14E87F3, 0x2AD95B60)
XTEA_DELTA = 0x9E3779B9
XTEA_ROUNDS = 32


def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def xtea_encrypt_block(v0, v1):
    """加密一个 8 字节块，返回 (v0, v1)。CTR 模式下加解密共用此函数生成密钥流。"""
    s = 0
    for _ in range(XTEA_ROUNDS):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + XTEA_KEY[s & 3]))) & 0xFFFFFFFF
        s = (s + XTEA_DELTA) & 0xFFFFFFFF
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + XTEA_KEY[(s >> 11) & 3]))) & 0xFFFFFFFF
    return v0, v1


def _keystream_block(counter):
    v0, v1 = xtea_encrypt_block(counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF)
    return struct.pack("<II", v0, v1)


def xtea_ctr_crypt(data: bytes, nonce: int) -> bytes:
    out = bytearray()
    counter = nonce
    for i in range(0, len(data), 8):
        chunk = data[i:i + 8]
        stream = _keystream_block(counter)
        out.extend(_xor_bytes(chunk, stream[:len(chunk)]))
        counter += 1
    return bytes(out)


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def encrypt_to_bin(plain: bytes, format_tag=None) -> bytes:
    """把明文特征文本加密成 feature.bin。"""
    if format_tag:
        plain = _set_format_tag(plain, format_tag)
    nonce = int.from_bytes(os.urandom(8), "little")
    cipher = xtea_ctr_crypt(plain, nonce)
    header = struct.pack(
        "<4sBBHIIQ",
        MAGIC,
        FORMAT_VERSION,
        ALGO_XTEA_CTR,
        HEADER_SIZE,
        len(plain),
        crc32(plain),
        nonce,
    )
    return header + cipher


def decrypt_from_bin(data: bytes) -> bytes:
    """解密 feature.bin，返回明文。校验 magic/长度/CRC。"""
    if len(data) < HEADER_SIZE:
        raise ValueError("文件太短，不是有效 feature.bin")
    magic, ver, algo, hlen, plain_len, expected_crc, nonce = struct.unpack("<4sBBHIIQ", data[:HEADER_SIZE])
    if magic != MAGIC:
        raise ValueError(f"magic 不匹配: {magic!r} (期望 {MAGIC!r})")
    if hlen != HEADER_SIZE or ver != FORMAT_VERSION or algo != ALGO_XTEA_CTR:
        raise ValueError(f"不支持的头/版本/算法: ver={ver} algo={algo} hlen={hlen}")
    if len(data) != HEADER_SIZE + plain_len:
        raise ValueError(f"长度不匹配: 文件 {len(data)} != {HEADER_SIZE}+{plain_len}")
    plain = xtea_ctr_crypt(data[HEADER_SIZE:], nonce)
    if crc32(plain) != expected_crc:
        raise ValueError("CRC32 校验失败")
    return plain


def _set_format_tag(plain: bytes, fmt: str) -> bytes:
    """替换/插入 #format 行。"""
    lines = plain.decode("utf-8", "replace").splitlines()
    has = any(l.startswith("#format") for l in lines)
    if has:
        lines = [f"#format {fmt}" if l.startswith("#format") else l for l in lines]
    else:
        lines = [f"#format {fmt}"] + lines
    return ("\n".join(lines) + "\n").encode("utf-8")


def pack_tar(cfg_path, out_path, icons_dir=None):
    """打包明文 tar：feature.cfg + 可选 app_icons/。"""
    with tarfile.open(out_path, "w") as tf:
        tf.add(cfg_path, arcname="./feature.cfg")
        if icons_dir and os.path.isdir(icons_dir):
            tf.add(icons_dir, arcname="./app_icons")
    return out_path


def pack_tarbin(bin_path, out_path, icons_dir=None):
    """打包高级版 tar.gz：feature.bin + 可选 app_icons/。"""
    with tarfile.open(out_path, "w:gz") as tf:
        tf.add(bin_path, arcname="feature.bin")
        if icons_dir and os.path.isdir(icons_dir):
            for root, _, files in os.walk(icons_dir):
                for fn in files:
                    full = os.path.join(root, fn)
                    rel = os.path.relpath(full, icons_dir)
                    tf.add(full, arcname="app_icons/" + rel.replace("\\", "/"))
    return out_path


def build_release(cfg_path, out_zip, version, icons_dir=None, note_bytes=None):
    """
    产出与官方发布包完全一致的三层结构：

        feature3.0_cn_<version>.zip
        └── feature3.0_cn_<version>/
            ├── feature3.0_cn_<version>-free.bin   (gzip 压缩的 tar)
            └── 升级说明.txt

    .bin 内部 = tar，含 ./feature.cfg 与 ./app_icons/*。
    """
    # 1) 生成 tar（./feature.cfg + ./app_icons）
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        tf.add(cfg_path, arcname="./feature.cfg")
        if icons_dir and os.path.isdir(icons_dir):
            tf.add(icons_dir, arcname="./app_icons")
    tar_bytes = tar_buf.getvalue()

    # 2) gzip 压缩（mtime=0，与官方包一致）
    gz = gzip.compress(tar_bytes, compresslevel=9, mtime=0)

    # 3) 外层 zip
    folder = f"feature3.0_cn_{version}"
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo(folder + "/"), b"")
        zf.writestr(f"{folder}/feature3.0_cn_{version}-free.bin", gz)
        if note_bytes:
            zf.writestr(f"{folder}/升级说明.txt", note_bytes)
    return out_zip


def _main():
    p = argparse.ArgumentParser(description="OAF 特征库打包/加密工具")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("tar")
    s.add_argument("cfg")
    s.add_argument("out_tar")
    s.add_argument("--icons", default=None)

    s = sub.add_parser("tarbin")
    s.add_argument("bin")
    s.add_argument("out_targz")
    s.add_argument("--icons", default=None)

    s = sub.add_parser("bin")
    s.add_argument("cfg")
    s.add_argument("out_bin")
    s.add_argument("--format", default=None, help="例如 v4.0，覆盖 #format 行")

    s = sub.add_parser("decrypt")
    s.add_argument("bin")
    s.add_argument("out_txt")

    s = sub.add_parser("release")
    s.add_argument("cfg")
    s.add_argument("out_zip")
    s.add_argument("--version", required=True, help="例如 26.4.11")
    s.add_argument("--icons", default=None)
    s.add_argument("--note", default=None, help="升级说明.txt 路径")

    a = p.parse_args()

    if a.cmd == "tar":
        out = pack_tar(a.cfg, a.out_tar, a.icons)
        print(f"wrote {out}")
    elif a.cmd == "tarbin":
        out = pack_tarbin(a.bin, a.out_targz, a.icons)
        print(f"wrote {out}")
    elif a.cmd == "bin":
        with open(a.cfg, "rb") as f:
            plain = f.read()
        blob = encrypt_to_bin(plain, a.format)
        with open(a.out_bin, "wb") as f:
            f.write(blob)
        print(f"wrote {a.out_bin} ({len(plain)} -> {len(blob)} bytes)")
    elif a.cmd == "decrypt":
        with open(a.bin, "rb") as f:
            blob = f.read()
        plain = decrypt_from_bin(blob)
        with open(a.out_txt, "wb") as f:
            f.write(plain)
        print(f"wrote {a.out_txt} ({len(plain)} bytes)")
    elif a.cmd == "release":
        note_bytes = None
        if a.note and os.path.exists(a.note):
            with open(a.note, "rb") as f:
                note_bytes = f.read()
        out = build_release(a.cfg, a.out_zip, a.version, a.icons, note_bytes)
        print(f"wrote {out}")


if __name__ == "__main__":
    _main()
