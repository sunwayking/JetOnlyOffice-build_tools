# 共享层变更必须保持 Desktop 无回归

Mobile Web 首版把 Desktop 无回归作为发布门禁：文档、电子表格和演示文稿必须通过上游既有测试，并在 Chromium、Firefox、WebKit 中完成打开、编辑、保存、协作和重开自动化回归。相对同一发布基线出现的 Desktop 行为退化一律阻止发布，Mobile 能力不能以牺牲现有 Desktop 功能为代价。
