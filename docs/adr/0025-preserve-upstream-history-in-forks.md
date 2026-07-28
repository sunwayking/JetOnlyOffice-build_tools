# 四个 fork 保留完整上游历史

DocumentServer、web-apps、sdkjs 和 build_tools 的空远程仓库使用对应上游完整 Git 历史初始化，从统一锁定的发布基线提交创建并推送 `develop`，同时保留只读 `upstream` remote。项目不采用压缩快照或孤立提交，以便长期同步上游修复、审计产品差异并追溯任意发布产物。
