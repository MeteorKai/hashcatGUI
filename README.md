# HashcatGUI

HashcatGUI 是一个面向 Windows 的 hashcat 图形界面工具，用来更方便地配置、运行和管理 hashcat 任务。

> 仅用于授权安全测试、密码恢复、教学与学习研究。请勿在未授权的系统、账号或数据上使用。

## 主要功能

- 支持直接粘贴 Hash 文本，或选择 Hash 文件。
- 支持 hashcat 常见攻击模式：字典攻击、掩码攻击、字典 + 掩码、掩码 + 字典、模板候选。
- 支持 Hash 类型选择、搜索和识别辅助。
- 支持字典、规则、掩码、字符集等资源管理。
- 支持自定义字典导入、预览、编辑、追加和去重。
- 支持任务队列，多个任务可以按顺序运行。
- 支持任务历史、日志查看、结果查看、结果导出和任务恢复。
- 支持 CPU/GPU 设备选择、负载配置和运行状态查看。
- 支持内置 hashcat 检测与更新。
- 支持 OpenAI 兼容接口，用于 Hash 咨询和任务日志分析。

## 目录说明

```text
src/                         React 前端代码
src-tauri/                   Tauri / Rust 后端代码
src-tauri/resources/hashcat/ 内置 hashcat 资源目录
src-tauri/resources/wordlists/ 字典资源目录
scripts/                     打包脚本
dist-portable/               完整便携版输出目录
dist-lite/                   轻量版输出目录
test-artifacts/              测试和截图产物
```

## 开发环境

需要先安装：

- Node.js
- pnpm
- Rust
- Tauri 2 所需的 Windows 构建依赖

安装依赖：

```powershell
pnpm install
```

启动前端开发服务：

```powershell
pnpm dev
```

启动 Tauri 开发模式：

```powershell
pnpm tauri dev
```

## 构建

构建前端：

```powershell
pnpm build
```

构建完整便携版：

```powershell
pnpm portable
```

完整便携版输出位置：

```text
dist-portable/HashcatGUI/HashcatGUI.exe
```

构建轻量版：

```powershell
pnpm portable:lite
```

轻量版输出位置：

```text
dist-lite/HashcatGUI/HashcatGUI.exe
```

## Hashcat 与资源

完整便携版会把 `src-tauri/resources/hashcat/` 复制到发布目录中。

轻量版不内置 hashcat，可以在软件内通过：

```text
设置 -> Hashcat 更新
```

下载或更新 hashcat，也可以在设置里选择自定义 hashcat 安装目录。

字典文件可以放在：

```text
src-tauri/resources/wordlists/
```

但请注意，`rockyou.txt` 这类大字典通常超过 GitHub 单文件 100MB 限制，不建议提交到 Git 仓库。

## AI 设置

AI 功能使用 OpenAI 兼容接口。打开软件右上角设置后，填写：

- Base URL
- API Key
- Model

然后点击测试连接，成功后保存即可。

AI 配置保存在本机应用数据目录中，不会写入仓库。

## GitHub 提交注意事项

不要把下面这些内容提交到普通 Git 仓库：

```text
dist-portable/
dist-lite/
src-tauri/resources/wordlists/rockyou.txt
*.exe
*.7z
*.zip
```

原因是这些文件通常体积很大，容易触发 GitHub 的 100MB 单文件限制或导致 push 超时。

如果已经提交过大文件，需要从 Git 历史中移除，而不是只在本地删除文件。

## 免责声明

本工具仅用于授权安全测试、密码恢复、教学与学习研究。

使用者应自行确认使用场景符合所在地法律法规和目标系统授权范围。开发者不对任何未授权使用、数据损失或法律风险承担责任。
