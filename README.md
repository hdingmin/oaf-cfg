# oaf-cfg

OpenAppFilter (OAF) 应用特征库基线 + 扩充工具。

基线来源：`feature3.0_cn_26.04.10`（free 明文版，v3.0 格式），版本号由本仓库自行迭代。

## 目录结构

```
oaf-cfg/
├── feature.cfg        # 明文特征库（主文件，含 #version 版本号）
├── app_icons/         # 应用图标
├── scripts/           # 扩充/打包工具
│   ├── feature_cfg.py       # feature.cfg 解析 / 增删改 / JSON 互转
│   ├── extract_features.py  # pcap → 候选域名/端口/指纹
│   └── pack_feature.py      # tar 打包 + feature.bin 加解密 (XTEA-CTR)
└── references/
    └── format.md      # 特征库格式 + 签名字段 + 提炼方法论
```

## 快速开始

依赖：Python 3 + scapy（`pip install scapy`）。

```powershell
# 查看特征库
python scripts/feature_cfg.py list feature.cfg

# 查看单个 App
python scripts/feature_cfg.py show feature.cfg 1002

# 新增 App（ID 遵循分类规律，避开官方已用 ID）
python scripts/feature_cfg.py add feature.cfg 15001 新App --sig "tcp;;;app.example.com;;" --inplace

# 打包 free 明文版
python scripts/pack_feature.py tar feature.cfg feature3.0_cn_<版本>-free --icons app_icons

# 打包高级加密版
python scripts/pack_feature.py bin feature.cfg feature.bin --format v4.0
```

## 版本迭代

每次扩充特征后，编辑 `feature.cfg` 的 `#version` 行，自增版本号，并 commit 一条清晰的变更说明（新增了哪个 App、ID、签名来源）。

## 说明

- 详细格式与签名方法论见 `references/format.md`。
- 特征提取完整工作流见技能 `oaf-feature-extraction`。
