# OCI 运行镜像使用 Ubuntu 24.04 离线组装

首版 OCI 运行镜像使用按 digest 锁定的 Ubuntu 24.04 基础镜像，只安装同一 source lock 本次生成的本地 DEB 和 bootstrap 阶段缓存且已校验摘要的运行依赖，镜像组装阶段禁止访问外网。官方 Dockerfile 中在线下载发布 DEB 和 apt 依赖的路径不能进入正式构建链。
