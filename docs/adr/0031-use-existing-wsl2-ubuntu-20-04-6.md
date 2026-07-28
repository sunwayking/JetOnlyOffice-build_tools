---
status: superseded by ADR-0032
---

# 使用现有 WSL2 Ubuntu 20.04.6 正式构建

首版由 Windows 本机负责编排，实际编译直接使用现有 WSL2 `Ubuntu` 实例中的 Ubuntu 20.04.6，不新建或升级到 Ubuntu 24.04，也不移植为 Windows 原生交叉工具链。本决策取代 ADR-0030，并明确偏离 build_tools 9.4 文档列出的 Ubuntu 24.04 验证环境；因此 20.04.6 的完整源码构建和产物回归必须作为项目自己的兼容性证明。
