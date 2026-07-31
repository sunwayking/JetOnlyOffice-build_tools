# Source lock 原生保存逐组件许可证

正式 source lock 的仓库许可证记录允许两种互斥形态：已有的单一仓库级声明保持不变；无法用一个仓库级 SPDX 表达式准确描述的输入使用 `scope: component`，保存 `payloadPatterns`、完整的组件和 payload 清单，以及每个 payload 对应的 SPDX 与不可变证据摘要。组件形态只能在所有匹配 payload 均完成审查后生成，不携带候选证据、原因或 unresolved 状态，也不得伪造仓库级聚合 SPDX。

Bootstrap 和 Verify 必须按 `payloadPatterns` 重新枚举锁定 tree，逐项复核 payload Git blob、SHA-256、证据 locator 和证据 SHA-256。对于 Git LFS payload，blob 和 SHA-256 绑定 Git pointer，内嵌证据则只从 `lfsObjects` 已绑定并验证的实体字节提取。许可证归档保存 Git blob、字体内嵌记录或 ZIP 成员中实际采用的授权字节；SPDX 为每个 `LicenseRef-*` 写入 `hasExtractedLicensingInfos`，CycloneDX 保留逐组件表达式、payload 和证据引用。发布验证器将 source lock、toolchain lock、两种 SBOM 与许可证归档交叉校验，任一缺失或漂移均阻止发布。

仓库级声明许可证本身若由 Git LFS 管理，`sha256` 继续绑定 Git pointer，
同时必须保存 `materializedSha256` 绑定归档和 SBOM 实际采用的许可证实体字节。
契约只允许在许可证路径同时出现在 `lfsObjects` 时存在该字段，并要求该路径
属于 LFS 时字段必填；打包和验证不得把 pointer 摘要与实体摘要混用。
