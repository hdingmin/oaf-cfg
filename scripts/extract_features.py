#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 pcap 抓包提取 OAF 应用候选特征。

从某个 MAC 设备的流量里，自动提取可用于生成 OAF 签名的线索：
  1. DNS 查询域名 (qname)
  2. TLS ClientHello 的 SNI
  3. HTTP Host 头
  4. TCP/UDP 目标端口（按协议聚合统计）
  5. （可选）payload 首 N 字节指纹，用于生成 dict 签名

用法:
    python extract_features.py in.pcap [--suggest] [--json out.json] [--top N]

输出是一份"候选特征报告"，供后续人工挑选并写入 feature.cfg。
依赖: scapy
"""
import argparse
import json
import sys
from collections import defaultdict

try:
    from scapy.all import rdpcap, DNS, DNSQR, TCP, UDP, IP, IPv6, Raw
except Exception as e:  # pragma: no cover
    print(f"需要 scapy: pip install scapy ({e})", file=sys.stderr)
    sys.exit(1)


def iter_pkts(path):
    return rdpcap(path)


def payload_of(pkt):
    if Raw in pkt:
        return bytes(pkt[Raw].load)
    return b""


def parse_tls_sni(data):
    """从 TLS 记录流里尽力提取 ClientHello 的 SNI。返回域名或 None。"""
    try:
        i = 0
        while i + 5 <= len(data):
            if data[i] != 0x16:  # not handshake
                return None
            length = int.from_bytes(data[i + 3:i + 5], "big")
            i += 5
            rec = data[i:i + length]
            i += length
            if len(rec) < 4 or rec[0] != 0x01:  # ClientHello
                continue
            # handshake header: type(1) + len(3)
            hs = rec[4:]
            if len(hs) < 34:
                continue
            # ClientHello: legacy_version(2) + random(32)
            pos = 2 + 32
            if pos + 1 > len(hs):
                continue
            sid_len = hs[pos]; pos += 1
            if pos + sid_len + 2 > len(hs):
                continue
            pos += sid_len
            cs_len = int.from_bytes(hs[pos:pos + 2], "big"); pos += 2
            if pos + cs_len + 1 > len(hs):
                continue
            pos += cs_len
            cm_len = hs[pos]; pos += 1
            if pos + cm_len + 2 > len(hs):
                continue
            pos += cm_len
            ext_len = int.from_bytes(hs[pos:pos + 2], "big"); pos += 2
            end = min(pos + ext_len, len(hs))
            while pos + 4 <= end:
                etype = int.from_bytes(hs[pos:pos + 2], "big")
                elen = int.from_bytes(hs[pos + 2:pos + 4], "big")
                pos += 4
                if etype == 0:  # server_name
                    # list len(2) + type(1) + name_len(2) + name
                    sn = hs[pos:pos + elen]
                    if len(sn) >= 5:
                        nl = int.from_bytes(sn[3:5], "big")
                        name = sn[5:5 + nl]
                        return name.decode("utf-8", "ignore")
                pos += elen
    except Exception:
        return None
    return None


def extract_http_host(data):
    try:
        head = data[:2048].decode("latin-1")
        for line in head.split("\r\n"):
            if line.lower().startswith("host:"):
                return line[5:].strip()
    except Exception:
        return None
    return None


def is_ip(pkt):
    return IP in pkt or IPv6 in pkt


def analyze(path, top_n=100):
    domains = defaultdict(lambda: {"ports": set(), "protos": set(), "src": set()})
    port_stats = defaultdict(int)          # (proto, dport) -> count
    proto_ports = defaultdict(set)         # proto -> {dport}
    payload_samples = []                   # (proto, dport, bytes)

    count = 0
    for pkt in iter_pkts(path):
        count += 1
        # DNS
        if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
            q = pkt[DNSQR].qname
            if q:
                q = q.decode("utf-8", "ignore").rstrip(".")
                if q:
                    domains[q]["src"].add("dns")
        # L4
        if TCP in pkt:
            proto, dport = "tcp", int(pkt[TCP].dport)
            port_stats[(proto, dport)] += 1
            proto_ports[proto].add(dport)
            data = payload_of(pkt)
            sni = parse_tls_sni(data)
            if sni:
                domains[sni]["ports"].add(dport)
                domains[sni]["protos"].add(proto)
                domains[sni]["src"].add("tls")
            host = extract_http_host(data)
            if host:
                domains[host]["ports"].add(dport)
                domains[host]["protos"].add(proto)
                domains[host]["src"].add("http")
            if data and len(payload_samples) < 2000:
                payload_samples.append((proto, dport, data[:16]))
        elif UDP in pkt:
            proto, dport = "udp", int(pkt[UDP].dport)
            port_stats[(proto, dport)] += 1
            proto_ports[proto].add(dport)
            data = payload_of(pkt)
            if data and len(payload_samples) < 2000:
                payload_samples.append((proto, dport, data[:16]))

    top_ports = sorted(port_stats.items(), key=lambda kv: -kv[1])[:top_n]
    return {
        "packet_count": count,
        "domains": {k: {"ports": sorted(v["ports"]), "protos": sorted(v["protos"]),
                        "src": sorted(v["src"])} for k, v in sorted(domains.items())},
        "ports": [{"proto": pr, "dport": dp, "count": c} for (pr, dp), c in top_ports],
        "proto_ports": {pr: sorted(ports) for pr, ports in sorted(proto_ports.items())},
        "payload_samples": [
            {"proto": pr, "dport": dp, "hex": b.hex()} for pr, dp, b in payload_samples[:top_n]
        ],
    }


def suggest(rep):
    """从分析结果生成候选签名文本。"""
    out = []
    for dom, meta in rep["domains"].items():
        for pr in meta["protos"]:
            ports = meta["ports"] or [""]
            for dp in ports:
                out.append(f"{pr};;{dp};{dom};;")
    for pr, dports in rep["proto_ports"].items():
        for dp in dports:
            out.append(f"{pr};;{dp};;;")
    return out


def _main():
    p = argparse.ArgumentParser(description="从 pcap 提取 OAF 候选特征")
    p.add_argument("pcap")
    p.add_argument("--json", default=None, help="输出 JSON 到文件")
    p.add_argument("--top", type=int, default=100)
    p.add_argument("--suggest", action="store_true", help="额外输出候选签名文本")
    a = p.parse_args()

    rep = analyze(a.pcap, a.top)

    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=2)
        print(f"wrote {a.json}")

    print(f"== 抓包统计: {rep['packet_count']} 包 ==")
    print("\n== 发现域名 (来源 dns/tls/http) ==")
    for dom, meta in rep["domains"].items():
        print(f"  {dom}\tports={meta['ports']}\tproto={meta['protos']}\tsrc={meta['src']}")

    print("\n== 高频目标端口 ==")
    for pr in rep["ports"][:30]:
        print(f"  {pr['proto']}/{pr['dport']}\t{pr['count']} 次")

    if a.suggest:
        print("\n== 候选签名 (供写入 feature.cfg，需人工筛选) ==")
        for s in suggest(rep):
            print(f"  {s}")


if __name__ == "__main__":
    _main()
