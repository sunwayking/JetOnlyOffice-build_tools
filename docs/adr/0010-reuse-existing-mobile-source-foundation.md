# 复用现有 Mobile 源码基座

JetOnlyOffice 以同一发布基线中现有的文档、电子表格和演示文稿 Mobile view、controller 与 store 为源码基座，补齐自有 `EditorUIController` 和共享编辑能力层，并依据 Android 真机截图重构信息架构与布局。相比从零重写，这能保留已经存在的编辑器集成和触控行为；现有占位实现、禁用编辑的门控及不符合产品规则的设备判断不被视为可直接发布的既有能力，Euro-Office 仍只作为参考。
