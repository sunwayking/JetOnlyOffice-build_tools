# Mobile 实施顺序优先验证 PDF 独立适配层

首版按公共 Mobile 框架、文档、PDF、电子表格、演示文稿的顺序实施。PDF 在文档之后复用已经验证的触控交互骨架，但由于同版本上游不存在 `apps/pdfeditor/mobile`，必须建立独立的 PDF Mobile adapter，接入可共享的 Desktop PDF 命令与控制器能力以及 SDKJS PDF 内核；将 PDF 提前到电子表格和演示文稿之前，可以尽早验证公共框架能否承载页面、批注、绘图、表单和签名等非文档型任务，避免公共框架被前三类现有 Mobile 结构固化。
