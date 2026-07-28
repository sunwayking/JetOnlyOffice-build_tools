# Mobile Web 保持宿主中立

Mobile Web 只使用标准 Web API 完成文件选择、相机、剪贴板、下载和分享，不依赖 JetTaskFlow 或特定 Android 应用的私有 JavaScript Bridge。Android WebView 宿主负责实现标准 WebView 文件选择器、运行时权限和下载回调契约，使同一份编辑器源码可以运行于 Android Chrome、不同 WebView 及 iPhone 浏览器环境。
