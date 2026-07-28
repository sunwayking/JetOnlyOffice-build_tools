# 协调发布使用机器可读证据清单

每个协调发布候选必须生成 `release-evidence.json`，以单一发布 ID 绑定 source lock、四仓 commit、构建环境 digest、全部产物 SHA-256 与 SBOM、命令覆盖、自动化结果、真机截图与性能数据、Desktop 无回归和许可证检查。CI 只消费可追溯的原始结果生成该清单，不接受人工勾选替代；任一必需项缺失或失败时，禁止将四仓提升到 `main` 或创建 `jetonlyoffice-vX.Y.Z` 正式标签。
