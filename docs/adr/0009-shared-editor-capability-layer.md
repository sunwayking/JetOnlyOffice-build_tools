# 共享编辑能力层并使用 Desktop 和 Mobile 双适配器

SDKJS 编辑内核、文档状态、协同、保存与撤销栈保持单一实现，Web Apps 从现有 Desktop controller 中提取共享命令、权限、选择对象、状态和设置接口，再由 Desktop 与 Mobile 分别提供界面适配器。三个编辑器共享 Mobile 工具栏、面板导航、设备分类和触控基础设施，Mobile 不复制整套 Desktop controller、不直接操作 Desktop DOM，也不建立第二套文档状态源。
