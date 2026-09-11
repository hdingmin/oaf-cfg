# OpenAppFilter 特征库格式详解

## 两种形态

| 形态 | 文件 | 格式 | 插件版本 | 说明 |
|------|------|------|---------|------|
| free 明文 | `feature.cfg` | v3.0 | 3.x | 明文文本，直接可编辑 |
| 高级加密 | `feature.bin` | v4.0 | 4.x+ | XTEA-CTR 加密容器，内容仍是文本 |

两者内核侧匹配逻辑相同，差别只是容器（明文 vs 加密）+ 内容格式版本标记。

## feature.cfg 明文格式 (v3.0)

```
#version v26.4.10
#format v3.0
#Author: destan19@126.com(destan19)
#id name:[proto;sport;dport;host url;request;dict;search str;ignore]
#class chat 1 聊天
1002 微信:[tcp;;;weixin.qq;;, tcp;;80;;/mmtls;, udp;;1100-1200;;;00:00|01:01|02:00]
```

- `#version` / `#format` 元信息。
- `#class <en> <id> <中文>` 分类定义。该行之后的 App 归属该分类，直到下一个 `#class`。
- App 行 = `<id> <名称>:[<签名1>,<签名2>,...]`。多条签名是"或"关系（命中任意一条即命中该 App）。
- `id` 是数字，命名有规律（见下）。

## 签名字段（8 字段，`;` 分隔，末尾空字段省略）

| 下标 | 字段 | 含义 | 示例 |
|------|------|------|------|
| 0 | proto | `tcp` / `udp` | `tcp` |
| 1 | sport | 源端口，可范围 | `1100-1200` |
| 2 | dport | 目标端口 | `80`、`443` |
| 3 | host | 域名/URL 子串匹配，支持 `*` 通配 | `weixin.qq`、`x19.*.netease.com` |
| 4 | request | HTTP 请求行/路径子串 | `/mmtls`、`d?host=`、`/beacon` |
| 5 | dict | 字节指纹 `偏移:值\|偏移:值`（十六进制），匹配 payload 固定偏移 | `01:f1\|02:03` |
| 6 | search | 搜索字符串 | — |
| 7 | ignore | 忽略标志 | — |

**语义要点**
- 空字段 = 不约束该维度。
- host/request/search 是子串匹配，不区分大小写通常由内核处理。
- dict 的 `偏移:值` 是"payload 第 N 字节必须等于某值"，用于没有明文域名/端口规律的私有协议（如游戏、即时通讯）。`1:66` 与 `01:66` 等价。
- 多个 dict 项用 `|` 分隔（同一个签名内是"与"关系，即这些偏移都要满足）。
- 多条签名（逗号分隔）是"或"关系。

## App ID 分类规律（v3.0 free 版观察值）

| 前缀 | 分类 |
|------|------|
| 1xxx | 聊天/即时通讯 |
| 2xxx | 游戏 |
| 3xxx | 视频 |
| 4xxx | 购物 |
| 5xxx | 音乐 |
| 6xxx | 招聘 |
| 7xxx | 下载 |
| 8xxx | 常用网站 |
| 10xxx | 生活 |
| 11xxx | 工具 |
| 14xxx | 金融 |

新增自定义 App 时，建议沿用该前缀规则，避免与官方 ID 冲突（自定义 ID 可另起不冲突的段）。

## feature.bin 加密容器 (v4.0)

见 `scripts/pack_feature.py` 头部注释。关键参数（硬编码于 `open-app-filter/src/fwx_feature.c`）：

- magic `FWXB`，格式版本 1，算法 1 = XTEA-CTR，头 24 字节。
- 头：`magic(4) + version(1) + algo(1) + header_size(2) + plain_len(4) + crc32(4) + nonce(8)`，全小端。
- 密钥 `{0x8f4c29a1, 0x73b6d502, 0xc14e87f3, 0x2ad95b60}`，delta `0x9e3779b9`，32 轮，CTR 模式（nonce 为计数器起点）。
- CRC32 为标准 IEEE 802.3（`zlib.crc32`）。

## 从抓包提炼签名的方法论

1. **优先域名**：有稳定域名的 App（大多数网站/视频/购物类），用 `proto;;;域名;;` 最稳、误报最低。域名来源：DNS 查询、TLS SNI、HTTP Host。
2. **端口辅助**：私有协议/游戏常靠端口。用 `proto;;端口;;;`。可加 dict 收紧。
3. **字节指纹**：对无域名、端口不固定的流量（QQ、游戏 UDP 等），取 payload 前 N 字节，找**连接建立后前几个包里稳定不变的偏移**做 dict。
4. **组合与去重**：一条 App 可写多条签名覆盖不同协议/端口；签名宁窄勿宽（宽签名会误伤别的 App）。
5. **验证**：签名写好后在目标设备上复测，确认命中该 App 且不误伤其它。

## 配套脚本

- `scripts/feature_cfg.py` — feature.cfg 解析/增删改/JSON 互转。
- `scripts/extract_features.py` — pcap → 候选域名/端口/指纹。
- `scripts/pack_feature.py` — 明文 tar 打包 + feature.bin 加解密。
