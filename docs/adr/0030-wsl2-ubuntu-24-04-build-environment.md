---
status: superseded by ADR-0031
---

# Windows 编排 WSL2 Ubuntu 24.04 正式构建

首版由 Windows 本机负责源码、缓存、任务和产物编排，实际编译在本机 WSL2 Ubuntu 24.04 环境中执行，以保留 build_tools 9.4 已验证的 Linux 构建条件；不移植为 Windows 原生交叉工具链。当前默认 WSL2 `Ubuntu` 经核验为 Ubuntu 20.04.6，只能视为现有环境，尚不满足本决策规定的正式构建环境。
