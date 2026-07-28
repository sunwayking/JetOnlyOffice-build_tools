# 使用项目控制的 Fork 和 develop 集成分支

JetOnlyOffice 的 DocumentServer、Web Apps、SDKJS 和构建系统分别由 `sunwayking/JetOnlyOffice-DocumentServer`、`sunwayking/JetOnlyOffice-web-apps`、`sunwayking/JetOnlyOffice-sdkjs`、`sunwayking/JetOnlyOffice-build_tools` 长期维护，日常集成开发统一进入各仓库的 `develop` 分支。这样能够让移动编辑实现、构建变更和对应源码保持可追溯，同时避免重新回到第三方预编译 bundle 注入路线。
