# 使用说明：URL 字典爆破扫描工具

本工具是一款用于对指定 URL 进行字典爆破扫描的实用程序。它自动发起 HTTP 请求，检查响应状态码并分类，将结果存储到不同的 Markdown 文件中。以下是详细的使用步骤：

---

## 功能概述

1. **字典爆破扫描**：针对目标 URL 使用字典文件逐项请求。
2. **分类保存**：
    1. **可访问**：状态码 2xx。
    1. **不可访问**：状态码 4xx。
    1. **其他**：状态码 3xx, 5xx 等。
3. **多目标扫描**：支持输入多个 URL 目标。
4. **多模式支持**：
    1. 延迟请求模式：降低扫描频率。
    1. 并发请求模式：快速扫描。
5. **扫描报告生成**：按状态分类生成 Markdown 格式报告。
6. 支持字典项后缀自定义，如 `.php`, `.html` 等常见后缀, 判断字典中是否包含相关后缀

如有问题，请联系管理员或参考相关文档。
