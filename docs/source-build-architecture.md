# JetOnlyOffice 源码构建架构

## 1. 目标

JetOnlyOffice 是长期自维护的 ONLYOFFICE 产品 fork。发布产物必须能够从项目控制的、版本一致的源码仓库完整生成。

本设计不把 Euro-Office 的镜像、bundle 或源码 checkout 放入生产构建依赖图。Euro-Office 只用于理解可能的实现方式。Mobile 编辑的视觉、信息架构和交互基准以 [Android 真机截图](mobile-design-reference.md) 为最高优先级参考；同版本 [Desktop Web 功能区](desktop-web-reuse.md) 用于补齐功能覆盖并提供可复用实现。

## 2. 架构原则

1. **一个发布基线**：所有仓库和子模块属于同一个已验证的 ONLYOFFICE 发布系列。
2. **一个源码锁**：tag 和 branch 只用于发现版本，构建只接受 commit 和内容摘要。
3. **一个构建入口**：CI 与开发者通过统一脚本调用构建，不手工复制产物。
4. **源码与产物一一对应**：每个镜像都能追溯到完整源码、工具链和依赖锁。
5. **构建与运行分离**：构建环境可以联网准备依赖；正式编译和打包阶段应支持无网络运行。
6. **失败关闭**：源码锁、许可证、测试或摘要不一致时不生成可发布镜像。

## 3. 目标仓库布局

```text
JetOnlyOffice/
├── sources/
│   ├── DocumentServer/          # 项目 fork，superproject
│   ├── web-apps/                # 项目 fork
│   ├── sdkjs/                   # 项目 fork
│   ├── build_tools/             # 项目 fork，统一构建编排
│   ├── core/                    # DocumentServer 锁定子模块
│   ├── server/                  # DocumentServer 锁定子模块
│   ├── core-fonts/
│   ├── dictionaries/
│   └── plugins/                 # 实际启用的插件源码
├── packaging/
│   ├── document-server-package/ # 软件包/运行目录生成
│   └── docker-documentserver/   # OCI 镜像组装
├── locks/
│   ├── sources.lock.json
│   ├── toolchain.lock.json
│   └── images.lock.json
├── scripts/
│   ├── bootstrap-source.ps1
│   ├── build.ps1
│   ├── package.ps1
│   └── verify.ps1
├── tests/
│   ├── integration/
│   ├── mobile/
│   └── release/
├── artifacts/                   # Git 忽略的构建输出
└── references/
    └── euro-office/             # 设计笔记、链接和差异分析，不是构建输入
```

DocumentServer 不只是 `web-apps` 和 `sdkjs`。它还通过子模块关联 `core`、`server`、字体、字典和插件。要实现“同一版本完整构建”，这些仓库也必须纳入 source lock。

## 4. 模块与接口

### 4.1 Source Resolver

接口：

```powershell
.\scripts\bootstrap-source.ps1 [-Offline]
```

职责：

- 根据 `sources.lock.json` 获取或验证项目 fork。
- 校验 commit、tree hash、remote 和子模块关系。
- 在线模式只负责准备缓存；离线模式验证构建所需内容已经齐备。
- 禁止把浮动 branch、tag 或镜像 `latest` 解析结果直接带入构建。

### 4.2 Build Orchestrator

接口：

```powershell
.\scripts\build.ps1 -Platform linux-amd64 -Configuration Release
```

职责：

- 调用项目 fork 的 `build_tools`。
- 构建 Web Apps、SDKJS、core、server、字体、主题和配置资源。
- 将所有输出写入一个带 source-lock digest 的 artifact 目录。
- 不下载 Euro-Office 产物，也不使用官方预编译移动编辑 addon。

### 4.3 Package Assembler

接口：

```powershell
.\scripts\package.ps1 -Platform linux-amd64
```

职责：

- 只读取 Build Orchestrator 的完整输出。
- 生成软件包、运行目录和 OCI 镜像。
- 生成 SBOM、许可证清单、对应源码归档、SHA-256 和 provenance。
- 禁止直接从另一个 DocumentServer 镜像复制应用 bundle。

### 4.4 Release Verifier

接口：

```powershell
.\scripts\verify.ps1 `
  -Image <immutable-image-digest> `
  -ReferenceArtifactManifestPath <independent-build-manifest>
```

职责：

- 校验镜像内版本、文件摘要与 source lock 的对应关系。
- 通过锁定的 Ubuntu builder 镜像执行缓存中摘要锁定的 Linux 验证工具，
  不在 Windows 宿主执行 Linux 二进制，也不读取宿主 `PATH` 的替代工具。
- 执行 DocumentServer 健康检查、JWT、WebSocket、callback/save 和版本链测试。
- 执行文档、电子表格、演示文稿和 PDF 的 Desktop 与 Mobile 矩阵。
- 输出机器可读结果；任何必需 gate 缺失时不得报告通过。

## 5. 版本锁设计

`locks/sources.lock.json` 至少应记录：

```json
{
  "productVersion": "<jetonlyoffice-version>",
  "repositories": {
    "DocumentServer": {
      "origin": "<project-fork-url>",
      "upstream": "https://github.com/ONLYOFFICE/DocumentServer.git",
      "commit": "<40-character-commit>",
      "tree": "<git-tree-hash>"
    }
  }
}
```

实际 lock 必须覆盖全部构建仓库，且在 fork 地址和版本映射确认后由脚本生成，不能手工用占位值作为构建输入。

首个 source lock 的提交图已经由 ADR-0027 固定为 DocumentServer `v9.4.0` 的实际 gitlink 图，不使用 web-apps 或 sdkjs 的相近 `.129` 标签拼接。上述 JSON 只说明 schema，生成脚本必须写入 ADR-0027 已确认的真实提交和 tree hash。

升级时创建新的 lock 文件并执行完整回归；不得在原 lock 上移动 commit。

## 6. Euro-Office 参考策略

Mobile 设计参考的优先级固定为：

1. **P0：Android 真机 ONLYOFFICE 9.4.1 截图及实际交互**，决定工具栏层级、面板结构、主要控件位置和状态转换。
2. **P1：同版本 ONLYOFFICE Desktop Web 编辑器**，补充完整功能清单，并优先复用命令、状态、权限和设置实现。
3. **P2：Euro-Office 公开实现**，只用于研究技术思路，不得覆盖 P0/P1，也不进入构建依赖。

偏离 P0 参考必须在 ADR 中记录原因、替代设计和真机验证证据，不能由实现者隐式决定。

JetOnlyOffice 产品需求、无障碍、触控可用性、错误处理和性能预算是验收约束，不属于可被上述参考优先级覆盖的设计素材。

允许：

- 阅读公开 issue、PR、设计讨论和源码。
- 记录移动编辑的用户行为、状态转换和测试场景。
- 比较模块划分并形成项目自己的 ADR。

不允许进入发布链：

- Euro-Office DocumentServer 镜像或其中提取的文件。
- Euro-Office 预编译 `app.js`、CSS、字体或其他 bundle。
- 运行时依赖 Euro-Office tag、branch、registry 或 CDN。
- 未记录来源、许可证和修改历史的源码复制。

移动编辑能力应在 JetOnlyOffice 的统一源码基线上实现。若后续决定复用任何 AGPL 源码，必须作为明确、可追溯的源码合并处理，并重新经过代码与合规审查；不能再以“参考”为名隐式复制。

## 7. 构建和发布 Gate

### Source Gate

- fork remote、commit、tree 和子模块与 source lock 完全一致。
- 工作树干净，无未记录补丁。
- 所有构建输入具备许可证和来源记录。

### Build Gate

- 锁定容器基础镜像和工具链 digest。
- 干净环境完成全量源码构建。
- 无网络编译阶段不发生依赖下载。
- 两次独立干净构建生成的 DEB、运行目录归档和 OCI 镜像 SHA-256 完全一致；任一差异都阻止发布。

### Functional Gate

- 文档、表格、演示和 PDF 均完成打开、完整编辑、保存、重开。
- callback、强制保存、版本链、并发冲突和断线恢复通过。
- Android WebView、目标移动浏览器和 Desktop 回归通过。
- ContextMenu、输入法、软键盘、字体和主题进入显式验收矩阵。

### Release Gate

- 镜像只包含本次源码构建产物。
- JWT 默认启用且没有默认密钥。
- SBOM、NOTICE、许可证、对应源码和构建证明齐全。
- 镜像 digest、source-lock digest 和测试报告绑定到同一版本记录。
- 生成 `release-evidence.json`，以同一发布 ID 绑定四仓 commit、构建环境 digest、全部产物 SHA-256 与 SBOM、命令覆盖、自动化结果、真机截图与性能数据、Desktop 无回归和许可证检查。
- `release-evidence.json` 任一必需项缺失或失败时，CI 禁止将四仓协调提升到 `main` 或创建正式标签。

## 8. 当前迁移规则

- 根目录 Git 仓库已初始化，但当前设计文件尚未形成初始提交。
- 四个项目远程仓库地址和 `develop` 分支策略已经确认，远程仓库当前为空，必须以保留上游完整历史的方式初始化。
- 新 Source Resolver 建立后，只有 `sources/` 下被 source lock 管理的 checkout 才能进入构建。
- 旧 Dockerfile 的 bundle 注入逻辑不得恢复。
