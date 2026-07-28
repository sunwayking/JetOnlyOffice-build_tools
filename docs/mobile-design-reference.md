# Mobile 编辑设计参考

## 1. 优先级

本目录归档的 Android 真机截图是 JetOnlyOffice Mobile 编辑功能的 **P0、最高优先级参考设计**。

同版本 ONLYOFFICE Desktop Web 编辑器是 **P1 功能与实现参考**。它可以补齐截图未覆盖的功能，并为 Mobile 提供共享命令、状态和设置模块，但不得以桌面布局覆盖本目录确定的移动端信息架构。详细规则见 [Desktop Web 复用设计](desktop-web-reuse.md)。

它们用于确定：

- 顶部主工具栏与底部快捷工具栏的分工；
- 编辑、插入、设置、协作等二级菜单的入口和层级；
- 二级面板的全宽布局、标签切换、关闭行为和滚动方式；
- 图标、列表、色块、开关、分隔线和选择状态的表达；
- 横屏编辑时文档画布与功能面板的空间关系。

后续实现若需要偏离截图，必须通过 ADR 记录原因并提供新的 Android 真机验证证据。

## 2. 采集环境

| 项目 | 值 |
|---|---|
| 采集日期 | 2026-07-28 |
| 设备 | Xiaomi `2409BRN2CC` (`pond`) |
| Android | 16 / API 36 |
| 物理屏幕 | 720 x 1640，density 320；编辑器横屏运行 |
| 应用 | `com.onlyoffice.documents` |
| 应用版本 | 9.4.1，versionCode 731 |
| 编辑器 | 文档、电子表格、演示文稿 |
| 测试文档 | `ONLYOFFICE Sample Document.docx`、`ONLYOFFICE Sample Spreadsheet.xlsx`、`ONLYOFFICE Sample Presentation.pptx` |

截图通过 ADB `screencap` 直接从真机取得，未裁切、未重绘。每张 PNG 旁保留同名 UIAutomator XML，用于查询可点击节点、resource id 和控件 bounds。

原始文件同时保存在系统截图目录：

```text
C:\Users\sunwa\Pictures\Screenshots\JetOnlyOffice-Mobile-Reference-20260728
C:\Users\sunwa\Pictures\Screenshots\JetOnlyOffice-Mobile-Reference-20260728-2
```

项目内的第二批扩展截图保存在：

```text
docs/reference/mobile/android-onlyoffice-20260728-extended
```

## 3. 截图目录

### 3.1 编辑主界面

![编辑主界面](reference/mobile/android-onlyoffice-20260728/01-editor-initial.png)

参考重点：顶部接受、撤销、重做、AI、编辑、插入、协作和设置入口；底部保留高频文本格式与键盘控制。

### 3.2 编辑菜单：文本

![文本编辑菜单](reference/mobile/android-onlyoffice-20260728/02-edit-menu.png)

参考重点：编辑面板覆盖屏幕下半区；使用“文本/段落”标签组织功能；字体与字号位于首行，常用样式形成等宽按钮组。

### 3.3 编辑菜单：段落

![段落编辑菜单](reference/mobile/android-onlyoffice-20260728/03-paragraph-menu.png)

参考重点：标签选中状态使用蓝色文字和短下划线；背景、高级、段落样式采用可继续进入的列表行。

### 3.4 插入菜单：表格

![插入表格菜单](reference/mobile/android-onlyoffice-20260728/04-add-menu.png)

参考重点：插入功能使用顶部图标标签；表格样式以四列密集网格展示，优先保证浏览和选择效率。

### 3.5 插入菜单：形状

![插入形状菜单](reference/mobile/android-onlyoffice-20260728/05-add-shapes.png)

参考重点：形状使用无卡片的规则网格，图形本身承担标签作用；文本框与线条和基础形状位于首屏。

### 3.6 插入菜单：图片

![插入图片菜单](reference/mobile/android-onlyoffice-20260728/06-add-image.png)

参考重点：图片来源使用图标加文字列表，保留本地图库、链接、相机和其他来源。

### 3.7 插入菜单：更多

![更多插入菜单](reference/mobile/android-onlyoffice-20260728/07-add-more.png)

参考重点：低频插入能力使用纵向列表和右箭头，包括批注、图表、分页符、目录和链接。

### 3.8 设置菜单

![设置菜单](reference/mobile/android-onlyoffice-20260728/08-settings-menu.png)

参考重点：设置使用独立全宽页面；标题显示当前文件名；直接开关与可进入的设置项混排。

### 3.9 协作菜单

![协作菜单](reference/mobile/android-onlyoffice-20260728/09-collaboration-menu.png)

参考重点：协作面板保持精简，只暴露批注和审阅两个任务入口。

## 4. 电子表格、演示文稿与上下文菜单

### 4.1 电子表格主界面与工具栏

![电子表格编辑主界面](reference/mobile/android-onlyoffice-20260728-extended/10-excel-editor-main.png)

参考重点：顶部保留文件、撤销/重做、编辑、插入和设置等全局命令；底部承载单元格格式、函数与工作表高频操作，公式栏保持常驻。

![电子表格编辑菜单](reference/mobile/android-onlyoffice-20260728-extended/11-excel-edit-menu.png)

参考重点：单元格格式通过底部全宽面板展开，属性按任务分组，不照搬 Desktop Web 的固定功能区。

![电子表格插入菜单](reference/mobile/android-onlyoffice-20260728-extended/12-excel-add-menu.png)

![电子表格公式菜单](reference/mobile/android-onlyoffice-20260728-extended/13-excel-formula-menu.png)

![电子表格形状菜单](reference/mobile/android-onlyoffice-20260728-extended/14-excel-shapes-menu.png)

![电子表格更多菜单](reference/mobile/android-onlyoffice-20260728-extended/15-excel-more-menu.png)

参考重点：表格、公式、形状和更多能力共享同一层级与关闭方式；密集选择项优先使用图标网格，低频命令使用列表。

### 4.2 电子表格长按菜单

![电子表格单元格长按菜单](reference/mobile/android-onlyoffice-20260728-extended/16-excel-cell-longpress-menu.png)

这张截图实际触发的是单元格 `C1` 的长按菜单，并非图片对象菜单。原始采集文件名曾误写为 `image-longpress`，项目归档已按真实行为更名，禁止把它当作图片上下文菜单实现依据。

![电子表格图表长按菜单](reference/mobile/android-onlyoffice-20260728-extended/17-excel-chart-longpress-menu.png)

参考重点：图表长按菜单提供剪切、复制、删除、编辑和图表属性入口；对象选中框、上下文菜单和底部对象快捷栏同时表达当前选择。

### 4.3 演示文稿主界面与工具栏

![演示文稿编辑主界面](reference/mobile/android-onlyoffice-20260728-extended/21-ppt-editor-main.png)

参考重点：左侧缩略图导航、中央画布、顶部全局工具栏和底部插入快捷栏形成四个稳定区域；Mobile 可以借用 Desktop Web 的幻灯片命令，但必须映射到这一空间结构。

![演示文稿编辑菜单](reference/mobile/android-onlyoffice-20260728-extended/22-ppt-edit-menu.png)

![演示文稿插入表格](reference/mobile/android-onlyoffice-20260728-extended/23-ppt-add-menu.png)

![演示文稿插入形状](reference/mobile/android-onlyoffice-20260728-extended/24-ppt-add-shapes.png)

![演示文稿插入图片](reference/mobile/android-onlyoffice-20260728-extended/25-ppt-add-image.png)

![演示文稿更多插入](reference/mobile/android-onlyoffice-20260728-extended/26-ppt-add-more.png)

![演示文稿设置菜单](reference/mobile/android-onlyoffice-20260728-extended/27-ppt-settings-menu.png)

参考重点：幻灯片主题、布局和过渡使用底部属性面板；插入菜单在表格、形状、图片和更多四个标签间切换；文件级设置使用独立全宽页面。

### 4.4 文字、图片和图表长按菜单

![演示文稿文字框长按菜单](reference/mobile/android-onlyoffice-20260728-extended/28-ppt-text-longpress-menu.png)

![文档文字长按菜单](reference/mobile/android-onlyoffice-20260728-extended/30-word-text-longpress-menu.png)

文字上下文命令随对象类型变化：普通文档文字包含剪切、复制、粘贴、删除、编辑、段落、链接和批注；演示文字框另外暴露形状与编辑文本入口。

![文档图表长按菜单](reference/mobile/android-onlyoffice-20260728-extended/31-word-chart-longpress-menu.png)

图表对象提供编辑、图表属性和编辑数据入口。它与电子表格中的图表菜单共同作为图表上下文行为参考，不能只依据其中一个编辑器推导公共菜单。

![文档图片长按菜单](reference/mobile/android-onlyoffice-20260728-extended/32-word-image-longpress-menu.png)

图片对象提供剪切、复制、粘贴、删除、编辑、图像属性和替换图像入口。为了取得可验证的独立图片对象，本次将 ADB 采集生成的 `addmenu.png` 临时插入样例文档；截图完成后在退出提示中选择“否”，没有把测试更改保存到样例文件。

## 5. PDF 编辑器与对象菜单

PDF 参考证据保存在：

```text
docs/reference/mobile/android-onlyoffice-20260728-pdf
```

### 5.1 查看与编辑主界面

![PDF 查看主界面](reference/mobile/android-onlyoffice-20260728-pdf/01-pdf-editor-main.png)

查看状态的顶部只保留退出、协作和设置，右下角浮动铅笔进入编辑状态。

![PDF 编辑主界面](reference/mobile/android-onlyoffice-20260728-pdf/02-pdf-edit-main.png)

编辑状态采用接受、撤销/重做、AI、编辑、插入、协作和设置的顶部结构；底部快捷栏随当前表格、文字或形状选择变化。本次真机应用将 PDF 打开在 `lib.editors.gdocs.ui.activities.DocsActivity`，说明 9.4.1 Android 端实际复用了文档编辑交互骨架，而不是暴露独立 PDF Activity。

### 5.2 编辑与插入面板

![PDF 文本编辑面板](reference/mobile/android-onlyoffice-20260728-pdf/03-pdf-edit-menu.png)

![PDF 段落编辑面板](reference/mobile/android-onlyoffice-20260728-pdf/04-pdf-edit-paragraph.png)

![PDF 表格编辑面板](reference/mobile/android-onlyoffice-20260728-pdf/05-pdf-edit-table.png)

PDF 编辑面板沿用文本、段落和表格标签，使用红色强调色区分当前任务；对象属性仍根据当前选择切换。

![PDF 插入表格](reference/mobile/android-onlyoffice-20260728-pdf/06-pdf-add-menu.png)

![PDF 插入形状](reference/mobile/android-onlyoffice-20260728-pdf/07-pdf-add-shapes.png)

![PDF 插入图片](reference/mobile/android-onlyoffice-20260728-pdf/08-pdf-add-image.png)

![PDF 插入更多](reference/mobile/android-onlyoffice-20260728-pdf/09-pdf-add-more.png)

插入面板使用表格、形状、图片和更多四个顶部标签，与文档编辑器共享网格和列表模式。图片入口包含图库、链接、拍照及其他标准来源；更多列表包含批注、图表、分页符、目录和链接。

### 5.3 设置、协作与对象上下文

![PDF 设置](reference/mobile/android-onlyoffice-20260728-pdf/10-pdf-settings.png)

![PDF 协作](reference/mobile/android-onlyoffice-20260728-pdf/11-pdf-collaboration.png)

设置继续采用文件名标题和全宽列表，协作面板保留批注与审阅两个入口。

![PDF 表格文字长按菜单](reference/mobile/android-onlyoffice-20260728-pdf/12-pdf-text-longpress.png)

![PDF 形状长按菜单](reference/mobile/android-onlyoffice-20260728-pdf/13-pdf-shape-longpress.png)

![PDF 形状编辑面板](reference/mobile/android-onlyoffice-20260728-pdf/14-pdf-shape-edit-menu.png)

表格文字长按菜单同时提供文本和表格上下文命令；形状长按菜单提供剪切、复制、粘贴、删除、编辑、形状和编辑文本，底部快捷栏同步切换为形状命令。形状编辑使用独立全宽页面承载样式、更改形状和排列等任务。

本轮真机样例未暴露独立的页面管理、绘图、表单创建或签名顶级面板。因此，上述截图是 Android 9.4.1 已显示交互的 P0 参考，但不构成 PDF 完整命令清单；同版本 Desktop PDF Editor 继续作为这些未显示内置能力的 P1 功能来源，JetOnlyOffice 必须为其设计 Mobile 入口，不能因真机样例未显示而排除。

## 6. 实现约束

- P0 参考覆盖的是视觉与交互，不代表可以复制应用二进制、图标资源或闭源实现。
- Desktop Web 的业务命令、状态计算和编辑器调用应优先下沉到共享模块；Desktop 与 Mobile 分别作为该 interface 的 adapter。
- Desktop Web 的固定工具栏、右侧栏、悬停菜单、密集对话框和键盘优先流程不能直接缩放后放入 Mobile。
- 控件名称、状态和可点击区域应结合配套 XML 建立自动化验收，不以肉眼相似作为唯一完成标准。
- 文档、表格、演示和 PDF 必须共享工具栏/面板的交互骨架，但各自保留真实截图证明的专用命令、画布结构和对象上下文菜单。
- 保存、加载、错误、断线、冲突、权限和软键盘状态未被本轮截图完整覆盖，必须作为后续真机采集任务补齐。
