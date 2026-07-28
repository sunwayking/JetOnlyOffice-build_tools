# 四仓采用协调分支与发布规则

DocumentServer、web-apps、sdkjs 和 build_tools 统一以 `develop` 作为日常开发和默认分支，`main` 只接收通过全部门禁并由同一 source lock 协调提升的发布提交，正式版本使用一致的 `jetonlyoffice-vX.Y.Z` 标签。禁止直接向 `main` 开发，避免四个仓库形成版本相同但源码组合不兼容的独立发布。
