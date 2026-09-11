#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenAppFilter (OAF) feature.cfg 解析 / 增删改 / 序列化工具。

feature.cfg 是 OAF 明文特征库（free 版，v3.0 格式），纯文本。结构：

    #version v26.4.10
    #format v3.0
    #Author: destan19@126.com(destan19)
    #id name:[proto;sport;dport;host url;request;dict;search str;ignore]
    #class chat 1 聊天
    1002 微信:[tcp;;;weixin.qq;;, tcp;;80;;/mmtls;, udp;;1100-1200;;;00:00|01:01|02:00]

每条 App = `<id> <名称>:[<签名1>,<签名2>,...]`，每个签名用 `;` 分成 8 个字段
（末尾空字段通常被省略）：

    0 proto      tcp / udp
    1 sport      源端口，可范围 "1100-1200"
    2 dport      目标端口
    3 host       域名/URL 子串匹配，支持 * 通配 (如 "x19.*.netease.com")
    4 request    HTTP 请求路径匹配 (如 "/mmtls"、"d?host=")
    5 dict       字节指纹 "偏移:值|偏移:值" (十六进制)，匹配 payload 固定偏移字节
    6 search     搜索字符串
    7 ignore     忽略标志

用法:
    python feature_cfg.py dump <in.cfg> [out.json]       # 解析为 JSON
    python feature_cfg.py list <in.cfg>                  # 列出所有 App
    python feature_cfg.py show <in.cfg> <id>             # 查看单个 App
    python feature_cfg.py add <in.cfg> <id> <名称> --sig "..." [--class "1"]
    python feature_cfg.py update <in.cfg> <id> --name 新名 --sig "..." [--append]
    python feature_cfg.py del <in.cfg> <id>
    python feature_cfg.py fromjson <in.json> <out.cfg>   # JSON -> cfg
"""
import argparse
import json
import re
import sys

# 签名 8 个字段名（顺序固定）
SIG_FIELDS = ["proto", "sport", "dport", "host", "request", "dict", "search", "ignore"]


def parse_signature(raw: str):
    """'tcp;;;weibo;;' -> ['tcp','','','weibo','','','','']"""
    parts = raw.split(";")
    while len(parts) < len(SIG_FIELDS):
        parts.append("")
    # 保留前 8 个字段，多余的合并进最后（容错）
    if len(parts) > len(SIG_FIELDS):
        parts = parts[: len(SIG_FIELDS) - 1] + [";".join(parts[len(SIG_FIELDS) - 1:])]
    return parts


def format_signature(fields):
    """8 字段 list -> 'tcp;;;weibo'，去掉末尾连续空字段的分号"""
    fields = list(fields) + [""] * (len(SIG_FIELDS) - len(fields))
    fields = fields[: len(SIG_FIELDS)]
    # 去掉末尾的空字段
    end = len(fields)
    while end > 0 and fields[end - 1] == "":
        end -= 1
    return ";".join(fields[:end])


class App:
    def __init__(self, app_id, name, signatures=None, category=None):
        self.id = str(app_id).strip()
        self.name = name
        self.signatures = signatures or []   # list[list[str]]
        self.category = category             # {'id','en','zh'} 或 None

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "signatures": [dict(zip(SIG_FIELDS, s)) for s in self.signatures],
        }

    @staticmethod
    def from_dict(d):
        sigs = []
        for s in d.get("signatures", []):
            if isinstance(s, list):
                sigs.append(list(s))
            elif isinstance(s, dict):
                sigs.append([s.get(f, "") for f in SIG_FIELDS])
        return App(d["id"], d["name"], sigs, d.get("category"))

    def sig_text(self, idx=None):
        if idx is not None:
            return format_signature(self.signatures[idx])
        return ",".join(format_signature(s) for s in self.signatures)

    def line(self):
        return f"{self.id} {self.name}:[{self.sig_text()}]"


class FeatureLib:
    def __init__(self, version="", fmt="", header_lines=None, classes=None, apps=None):
        self.version = version
        self.format = fmt
        self.header_lines = header_lines or []   # 原样保留的注释行(不含 version/format/class)
        self.classes = classes or []             # list[dict]
        self.apps = apps or []                   # list[App]

    def find(self, app_id):
        app_id = str(app_id).strip()
        for a in self.apps:
            if a.id == app_id:
                return a
        return None

    def to_dict(self):
        return {
            "version": self.version,
            "format": self.format,
            "header": self.header_lines,
            "classes": self.classes,
            "apps": [a.to_dict() for a in self.apps],
        }


# 匹配 "#class chat 1 聊天" -> (id='1', en='chat', zh='聊天')
CLASS_RE = re.compile(r"^#class\s+(\S+)\s+(\S+)\s*(.*)$")
# 匹配 "#version v26.4.10"
VERSION_RE = re.compile(r"^#version\s+(\S+)")
FORMAT_RE = re.compile(r"^#format\s+(\S+)")
# 匹配 "1002 微信:[...]"
APP_RE = re.compile(r"^(\d{2,6})\s+(\S+)\s*:\s*\[(.*)\]$")


def parse(text):
    lib = FeatureLib()
    category_by_line = {}
    last_class = None
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        s = line.strip()
        if not s:
            continue
        if s.startswith("#class"):
            m = CLASS_RE.match(s)
            if m:
                cls = {"en": m.group(1), "id": m.group(2), "zh": m.group(3).strip()}
                lib.classes.append(cls)
                last_class = cls
            continue
        if s.startswith("#version"):
            m = VERSION_RE.match(s)
            if m:
                lib.version = m.group(1)
            continue
        if s.startswith("#format"):
            m = FORMAT_RE.match(s)
            if m:
                lib.format = m.group(1)
            continue
        if s.startswith("#"):
            lib.header_lines.append(line)
            continue
        m = APP_RE.match(s)
        if m:
            app_id, name, sigbody = m.group(1), m.group(2), m.group(3)
            sigs = []
            for part in split_sigs(sigbody):
                part = part.strip()
                if part:
                    sigs.append(parse_signature(part))
            lib.apps.append(App(app_id, name, sigs, dict(last_class) if last_class else None))
    return lib


def split_sigs(body):
    """按逗号拆分签名，但要容忍 dict 里不含逗号的情况（OAF 用逗号分隔多签名，dict 用 | 分隔）。"""
    return body.split(",")


def serialize(lib):
    lines = []
    if lib.version:
        lines.append(f"#version {lib.version}")
    if lib.format:
        lines.append(f"#format {lib.format}")
    for h in lib.header_lines:
        lines.append(h)
    # 按 app 首次出现的 category 顺序，交错输出 #class 与 app 行，
    # 以保留 "app 归属哪个分类" 的隐含关系。
    seen = set()
    for app in lib.apps:
        c = app.category
        if c and c.get("id") not in seen:
            en = c.get("en", "")
            zh = f" {c.get('zh','')}" if c.get("zh") else ""
            lines.append(f"#class {en} {c['id']}{zh}".rstrip())
            seen.add(c["id"])
        lines.append(app.line())
    return "\n".join(lines) + "\n"


def add_app(lib, app_id, name, sig_strings, category=None, replace=False):
    existing = lib.find(app_id)
    sigs = [parse_signature(s) for s in sig_strings]
    if existing and not replace:
        raise ValueError(f"App {app_id} 已存在，用 --replace 覆盖")
    app = App(app_id, name, sigs, category)
    if existing and replace:
        for i, a in enumerate(lib.apps):
            if a.id == app_id:
                lib.apps[i] = app
                return app
    lib.apps.append(app)
    return app


def update_app(lib, app_id, name=None, sig_strings=None, append=False):
    app = lib.find(app_id)
    if not app:
        raise ValueError(f"App {app_id} 不存在")
    if name:
        app.name = name
    if sig_strings is not None:
        new_sigs = [parse_signature(s) for s in sig_strings]
        if append:
            app.signatures.extend(new_sigs)
        else:
            app.signatures = new_sigs
    return app


def del_app(lib, app_id):
    lib.apps = [a for a in lib.apps if a.id != str(app_id).strip()]


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return parse(f.read())


def save(lib, path):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(serialize(lib))


def _main():
    p = argparse.ArgumentParser(description="OAF feature.cfg 解析/编辑工具")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("dump")
    s.add_argument("src")
    s.add_argument("out_json", nargs="?")

    s = sub.add_parser("fromjson")
    s.add_argument("src_json")
    s.add_argument("out_cfg")

    s = sub.add_parser("list")
    s.add_argument("src")

    s = sub.add_parser("show")
    s.add_argument("src")
    s.add_argument("app_id")

    s = sub.add_parser("add")
    s.add_argument("src")
    s.add_argument("app_id")
    s.add_argument("name")
    s.add_argument("--sig", action="append", required=True)
    s.add_argument("--class", dest="cat", default=None)
    s.add_argument("--replace", action="store_true")
    s.add_argument("--inplace", action="store_true", help="直接写回 src")

    s = sub.add_parser("update")
    s.add_argument("src")
    s.add_argument("app_id")
    s.add_argument("--name", default=None)
    s.add_argument("--sig", action="append", default=None)
    s.add_argument("--append", action="store_true")
    s.add_argument("--inplace", action="store_true")

    s = sub.add_parser("del")
    s.add_argument("src")
    s.add_argument("app_id")
    s.add_argument("--inplace", action="store_true")

    a = p.parse_args()

    if a.cmd == "dump":
        lib = load(a.src)
        data = lib.to_dict()
        out = a.out_json or (a.src + ".json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"wrote {out} ({len(lib.apps)} apps)")
    elif a.cmd == "fromjson":
        with open(a.src_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        lib = FeatureLib(
            version=data.get("version", ""),
            fmt=data.get("format", ""),
            header_lines=data.get("header", []),
            classes=data.get("classes", []),
            apps=[App.from_dict(d) for d in data.get("apps", [])],
        )
        save(lib, a.out_cfg)
        print(f"wrote {a.out_cfg} ({len(lib.apps)} apps)")
    elif a.cmd == "list":
        lib = load(a.src)
        for app in lib.apps:
            print(f"{app.id}\t{app.name}\t{len(app.signatures)} sigs")
    elif a.cmd == "show":
        lib = load(a.src)
        app = lib.find(a.app_id)
        if not app:
            print(f"App {a.app_id} 不存在", file=sys.stderr)
            sys.exit(1)
        print(f"id={app.id} name={app.name} category={app.category}")
        for i, s in enumerate(app.signatures):
            print(f"  [{i}] {format_signature(s)}")
    elif a.cmd == "add":
        lib = load(a.src)
        cat = None
        if a.cat:
            cat = {"id": a.cat, "en": "", "zh": ""}
        add_app(lib, a.app_id, a.name, a.sig, category=cat, replace=a.replace)
        if a.inplace:
            save(lib, a.src)
            print(f"added {a.app_id} to {a.src}")
        else:
            print(lib.find(a.app_id).line())
    elif a.cmd == "update":
        lib = load(a.src)
        update_app(lib, a.app_id, a.name, a.sig, append=a.append)
        if a.inplace:
            save(lib, a.src)
            print(f"updated {a.app_id}")
        else:
            print(lib.find(a.app_id).line())
    elif a.cmd == "del":
        lib = load(a.src)
        del_app(lib, a.app_id)
        if a.inplace:
            save(lib, a.src)
            print(f"deleted {a.app_id}")
        else:
            print(f"would delete {a.app_id}")


if __name__ == "__main__":
    _main()
