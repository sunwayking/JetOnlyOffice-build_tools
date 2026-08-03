# Source lock 原生保存逐组件许可证

正式 source lock 的仓库许可证记录允许两种互斥形态：已有的单一仓库级声明保持不变；无法用一个仓库级 SPDX 表达式准确描述的输入使用 `scope: component`，保存 `payloadPatterns`、完整的组件和 payload 清单，以及每个 payload 对应的 SPDX 与不可变证据摘要。组件形态只能在所有匹配 payload 均完成审查后生成，不携带候选证据、原因或 unresolved 状态，也不得伪造仓库级聚合 SPDX。

Bootstrap 和 Verify 必须按 `payloadPatterns` 重新枚举锁定 tree，逐项复核 payload Git blob、SHA-256、证据 locator 和证据 SHA-256。对于 Git LFS payload，blob 和 SHA-256 绑定 Git pointer，内嵌证据则只从 `lfsObjects` 已绑定并验证的实体字节提取。许可证归档保存 Git blob、字体内嵌记录或 ZIP 成员中实际采用的授权字节；SPDX 为每个 `LicenseRef-*` 写入 `hasExtractedLicensingInfos`，CycloneDX 保留逐组件表达式、payload 和证据引用。发布验证器将 source lock、toolchain lock、两种 SBOM 与许可证归档交叉校验，任一缺失或漂移均阻止发布。

锁定 payload 的完整授权若只存在于另一个公开镜像，使用独立的
`repository-git-blob` 证据类型。证据镜像必须是 active build input，并以相同
component id 和 SPDX 映射一份逐字节一致的 reference payload。source lock
同时绑定消费侧与证据侧的 commit、tree、payload blob/SHA-256 及 license
blob/SHA-256；打包阶段只能从已 materialize 的锁定 checkout 提取许可证。
同仓引用、未锁定镜像、非逐字节匹配和映射漂移均失败关闭。

一个组件表达式包含多个 `LicenseRef-*` 时，每条 evidence 必须用排序后的
`licenseRefs` 明确声明其授权文本归属于哪些自定义许可证；标准 SPDX 许可证证据
使用空数组。Resolver 要求表达式中的每个 LicenseRef 至少被一条 evidence 覆盖，
打包器和验证器只把该条 evidence 的文本写入这些标识，禁止把组件全部证据复制给
每个 LicenseRef。

仓库级声明许可证本身若由 Git LFS 管理，`sha256` 继续绑定 Git pointer，
同时必须保存 `materializedSha256` 绑定归档和 SBOM 实际采用的许可证实体字节。
契约只允许在许可证路径同时出现在 `lfsObjects` 时存在该字段，并要求该路径
属于 LFS 时字段必填且等于对应 LFS 对象 OID；打包和验证不得把 pointer 摘要
与实体摘要混用。
