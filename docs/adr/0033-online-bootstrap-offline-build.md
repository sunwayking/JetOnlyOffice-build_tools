# 联网 bootstrap 与断网 build 分离

构建链分为两个明确阶段：`bootstrap` 可以联网，但只能按 source lock 下载源码和依赖、校验摘要并写入本地缓存；正式 `build` 必须禁用网络，只能消费 source lock 和带摘要的缓存内容。build_tools 原有的自动拉取行为必须受此边界约束，任何缺失输入都应使离线构建失败，而不是临时访问远端补齐。
