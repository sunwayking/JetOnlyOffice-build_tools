# Desktop Web 功能复用设计

## 1. 定位

同版本 ONLYOFFICE Desktop Web 编辑器是 JetOnlyOffice Mobile 编辑功能的 **P1 参考**。

它的价值包括两部分：

1. **功能参考**：Desktop Web 覆盖移动截图没有展示的完整编辑、插入、审阅、设置和状态反馈能力。
2. **实现复用**：同一源码基线中的命令、状态、权限判断、编辑器调用和通用数据可以下沉为共享模块。

Desktop Web 不是 Mobile 的布局模板。Mobile 的工具栏层级、二级面板、触控尺寸和横竖屏空间关系仍以 Android 真机 P0 截图为准。

## 2. 复用 seam

共享模块应提供面向编辑能力的 interface，例如：

```text
EditorCommand.execute(command, payload)
EditorState.observe(scope)
EditorCapability.resolve(selection, permissions)
EditorSettings.read/write(scope)
```

具体命令名称和参数需要在源码盘点后确定。目标是把复杂的 SDKJS 调用、权限、选择对象和状态同步隐藏在共享模块内部。

Desktop 与 Mobile 分别实现界面 adapter：

```text
Desktop Toolbar / RightMenu ─┐
                              ├─ Shared editor modules ─ SDKJS
Mobile Toolbar / Panels ─────┘
```

测试通过共享 interface 验证行为，再分别验证 Desktop 和 Mobile adapter 的展示与触控交互。不要让 Mobile 直接调用 Desktop view，也不要复制 Desktop controller 后形成两套命令逻辑。

## 3. 候选复用矩阵

| Desktop Web 功能区 | 参考源码 | Mobile 形态 | 复用策略 |
|---|---|---|---|
| 顶部 Toolbar | `documenteditor/main/app/view/Toolbar.js`、`controller/Toolbar.js` | 顶部主入口 + 底部快捷栏 | 复用命令、权限、选中/禁用状态；重做界面 adapter |
| 右侧属性区 | `RightMenu.js`、`ParagraphSettings.js`、`ImageSettings.js`、`TableSettings.js`、`ShapeSettings.js`、`ChartSettings.js` | 编辑二级面板和可进入的高级页面 | 复用设置模型与 SDKJS 调用；按触控任务重新分组 |
| 文档画布交互 | `DocumentHolder.js`、`DocumentHolderExt.js` | 选区、对象焦点、长按和上下文操作 | 复用能力判断和命令；Mobile 提供触控 adapter |
| 文件功能区 | `FileMenu.js`、`FileMenuPanels.js` | 设置全屏页 | 复用文件信息、下载、打印和保护逻辑；简化导航 |
| 批注与审阅 | `common/main/lib/controller/Comments.js`、`ReviewChanges.js` | 协作二级菜单 | 复用事件与状态；使用 Mobile 列表/详情页 |
| 字体与颜色 | `Fonts.js`、`ComboBoxFonts.js`、`ColorPalette.js`、`ThemeColorPalette.js` | 字体选择页和触控色板 | 复用数据、主题色和最近使用项；重做触控界面 |
| 插入能力 | `InsertTableDialog.js`、链接/图片/图表相关设置 | 插入顶部标签和列表/网格 | 复用校验与插入命令；改为分步触控流程 |
| 状态栏 | `Statusbar.js` | 设置项、浮层或按需显示 | 选择性复用页码、缩放、语言、视图状态 |
| 高级设置 | 各类 `*SettingsAdvanced.js` 和通用 Dialog | 独立全屏页面 | 复用 schema、读写和校验；避免桌面密集弹窗 |

表格和演示编辑器使用同样方法盘点其 `Toolbar`、`RightMenu`、`DocumentHolder`、`Statusbar` 和 Settings 模块，优先抽取三个编辑器可共享的 interface。

### 3.1 PDF 签名源码边界

锁定候选基线中的签名存在两个不同概念，Mobile adapter 不得混用：

- `apps/common/main/lib/view/PdfSignDialog.js` 提供上传、手写和键入三种外观签名，不涉及证书验证；
- `apps/pdfeditor/main/app/controller/Main.js` 明确将 `isSignatureSupport` 设为 `false`，被注释的启用条件还要求 Desktop App、离线环境和底层签名支持，因此证书数字签名不是同版本 Desktop Web 的可用内置命令；
- `apps/pdfeditor/main/app/controller/DocumentHolderExt.js` 保留查看证书和移除签名等处理路径，但不能据此宣称浏览器端可以创建或完整验证证书数字签名；
- `sdkjs/pdf/src/forms/signature.js` 定义 PDF 签名字段类型，签名字段、外观签名和证书数字签名仍须在命令覆盖清单中分项记录。

首版 Mobile 必须完整适配外观签名和签名表单字段。已有证书数字签名只能展示底层引擎实际返回的验证状态，缺少可信结果时显示“未验证”；创建新的证书数字签名需要后续独立的 Web PKI 与证书提供方设计。

### 3.2 PDF 永久脱敏

`apps/pdfeditor/main/app/controller/RedactTab.js` 和对应 view 已提供标记脱敏、当前页或页范围脱敏、查找并标记以及应用脱敏等命令，并在离开未应用状态时要求用户选择应用或放弃。Mobile 将这些命令归入“编辑 → 脱敏”，但不能把视觉上的黑色覆盖当成完成：测试必须检查保存并重开后的文字搜索、复制、对象与内容流，证明目标内容已经从输出中移除。

## 4. 可以直接共享的实现

满足以下条件时，应优先移动到共享模块，而不是为 Mobile 重写：

- 不依赖 Desktop DOM、固定尺寸、鼠标或键盘事件；
- 输入是编辑器状态、选择对象、权限或明确 payload；
- 输出是命令结果、可观察状态或结构化设置；
- 错误模式和异步生命周期可以通过 interface 表达；
- Desktop 与 Mobile 至少存在两个真实 adapter。

优先候选包括：

- 编辑命令及 SDKJS 调用封装；
- `canEdit`、权限与功能可用性计算；
- selection/focus object 到设置类型的映射；
- 字体、颜色、样式、表格模板等数据提供者；
- undo/redo、保存、批注、审阅和冲突状态；
- 设置读取、更新、校验和持久化。

## 5. 需要 Mobile adapter 的内容

- 工具栏按钮编排和溢出策略；
- RightMenu 到底部/全屏二级面板的映射；
- 多级菜单到标签、列表、网格或分步流程的映射；
- hover、右键和拖放到点击、长按和手势的映射；
- 键盘快捷键优先流程到软键盘与触控流程的映射；
- 桌面 Dialog 到可滚动全屏页的映射；
- 横屏、竖屏、软键盘弹出和安全区域处理。

## 6. 不应挪用的内容

- Desktop view 的 DOM 或样式文件；
- 固定宽度工具栏、右侧栏和对话框尺寸；
- 依赖 hover 的可发现性；
- 多层级级联菜单；
- 小于移动触控目标的图标或密集控件；
- 只通过鼠标右键或键盘快捷键可达的流程；
- Desktop controller 中与 view 生命周期紧耦合的逻辑。

## 7. 实施顺序

1. 为文档编辑器建立 Desktop 功能清单，并与 P0 截图逐项映射。
2. 选择文本格式、段落、插入、批注四条 tracer-bullet 流程。
3. 抽取共享 interface，保留现有 Desktop adapter，并新增 Mobile adapter。
4. 在共享 interface 上验证命令、权限和状态，在真机上验证 Mobile 展示与触控。
5. 扩展到图片、表格、形状、图表、审阅和高级设置。
6. 将相同 interface 推广到 Spreadsheet 和 Presentation，避免三个编辑器各自复制一套 Mobile 基础设施。

## 8. 后续证据

当前 P1 判断基于同版本源码结构。源码构建环境可运行后，还需要补充 Desktop Web 的以下截图和交互记录：

- 默认编辑界面及工具栏展开态；
- 文本、段落、图片、表格、形状和图表属性区；
- 插入、批注、审阅、文件和高级设置流程；
- 不同选择对象和权限下的可见、禁用和选中状态；
- Desktop 命令与 Mobile 命令产生相同 SDKJS 结果的对照证据。
