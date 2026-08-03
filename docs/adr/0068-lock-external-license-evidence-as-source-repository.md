# 外部许可证证据先进入锁定源码镜像

上游 tree 不能完整证明逐 payload 许可证时，审计器不得直接读取 Debian、Ubuntu
或其他外部 URL。所采用的 payload 对照字节和许可证文本必须先进入
`sunwayking/JetOnlyOffice-*` 公开镜像，并以独立、固定 commit 的普通 Git blob
保存；许可证证据镜像自身也必须完成逐组件许可证审查。

`repository-git-blob` 证据同时绑定原 payload 的 path/blob/SHA-256、证据仓 ID、
字节对照 path/blob/SHA-256，以及许可证 path/blob/SHA-256。Resolver 只接受证据
仓中 SPDX 相同、组件 ID 相同且已用本仓 `git-blob` 映射的记录，并逐字节比较
原 payload 与对照 payload；本仓 `git-blob` 记录也必须绑定许可证 locator 的
Git blob，供 source lock 与 license audit 契约闭合跨仓映射。证据仓必须由不可变
tag 选择，证据 path 不得使用 Git LFS，避免许可证审计隐式
联网。Bootstrap、Verify、许可证归档和两种 SBOM 必须离线重放并保留完整引用；
任一仓、blob、映射、摘要或字节漂移都保持失败关闭。
