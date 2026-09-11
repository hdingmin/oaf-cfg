# 变更日志

记录每次对特征库的改动。版本号在 `feature.cfg` 的 `#version` 行迭代。

格式：每条 App 记录 **ID / 名称 / 分类 / 签名 / 来源 / 抓包设备**。

---

## v26.4.11 — 2026-09-11

### 新增 App

| ID | 名称 | 分类 | 签名 | 图标 |
|----|------|------|------|------|
| 3300 | 小小优趣 | video (3) | `tcp;;;ukids.cn` | app_icons/3300.png |

- **特征来源**：抓包设备 `192.168.3.228`（MAC `72:f0:f4:2c:b7:17`）
  - `fastapi.ukids.cn`（TLS SNI，443）
  - `vodtc.ukids.cn`（HTTP Host，80，视频流）
- **打包**：`releases/feature3.0_cn_26.4.11.zip`
- **App 总数**：311 → 312

## v26.4.10 — 基线

- 基线库：`feature3.0_cn_26.04.10-free`（free 明文版，v3.0 格式，311 个 App），来自 OpenAppFilter 官方 free 特征库。
