# 使用 Docker Ubuntu 24.04 正式构建

首版由 Windows 本机通过 Docker Desktop `desktop-linux` 上下文编排，在按镜像摘要锁定的 Ubuntu 24.04 Linux/amd64 容器中执行全部编译，不直接使用 Windows 工具链或宿主 WSL 发行版。本决策取代 ADR-0031，重新采用 build_tools 9.4 文档和 Dockerfile 已验证的 Ubuntu 24.04 环境；当前本机 Docker Linux 引擎已核验可用，并提供 16 CPU 与约 15.6 GiB 内存。
