# GoPhantom

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-blue.svg)](https://go.dev/)
[![Target](https://img.shields.io/badge/target-windows%2Famd64-blue.svg)](https://learn.microsoft.com/windows/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**GoPhantom** 是一个基于 Go 的 Windows Loader 生成器，面向授权红队演练、受控安全研究和防御技术验证场景。它通过模板化构建流程，将输入的 payload 与诱饵文件打包为 `windows/amd64` 可执行文件。

这个项目现在更偏向一个可维护的工程工具，而不是一次性脚本：命令行配置集中管理，Loader 源码由多个模板组合生成，测试会覆盖典型模板组合并进行交叉编译校验。

> **使用边界**：本项目仅限在自有环境、授权实验室或明确书面授权的安全评估中使用。请勿将其用于第三方系统、网络、设备或用户。

## 当前状态

| 项目 | 状态 |
| --- | --- |
| 开发语言 | Go 1.21+ |
| 生成目标 | `windows/amd64` |
| 构建平台 | macOS、Linux、Windows 均可交叉编译 |
| 测试命令 | `go test ./...` |
| 模板覆盖 | 默认模式、env-bind、indirect-syscall、module-stomping、mem-obf、evasion snippets 等组合 |
| 可复现构建 | 通过 `GOPHANTOM_SALT` 支持，包括 env-bind salt 与构建期随机选择 |

## 设计目标

- 让生成器行为尽量显式、可测、可回归。
- 用清晰的 flag 管理 Loader 变体，避免手工改模板。
- 保证模板组合在功能扩展后仍能编译通过。
- 文档与测试状态保持一致，不夸大实际能力。
- 将使用场景限定在授权研究、内部验证和实验室环境。

## 架构概览

GoPhantom 采用两阶段模型：生成阶段和运行阶段。

```text
输入文件 + 命令行参数
        |
        v
generator.go
  - 参数校验
  - 读取输入文件
  - 派生构建密钥与 salt
  - 渲染 Loader 模板
  - 交叉编译 windows/amd64
        |
        v
生成 loader.exe
```

### 主要组件

| 路径 | 说明 |
| --- | --- |
| `generator.go` | CLI 入口、配置校验、资产准备、模板渲染与交叉编译编排 |
| `internal/keymgr/` | 密钥和 salt 派生逻辑，包含可复现构建与测试用随机源注入 |
| `internal/knowledge/` | 可选技术片段的结构化元数据 |
| `templates/loader.go.tmpl` | 生成 Loader 的顶层模板 |
| `templates/_crypto.go.tmpl` | 运行时解密与环境绑定密钥重建逻辑 |
| `templates/_execute.go.tmpl` | 运行时执行路径模板 |
| `templates/_sandbox.go.tmpl` | 环境评分检测逻辑 |
| `templates/_syscall.go.tmpl` | 可选 syscall 支持代码 |
| `templates/_cleanup.go.tmpl` | 可选清理逻辑 |
| `generator_test.go` | 配置校验、可复现构建、模板渲染与交叉编译回归测试 |

## 功能矩阵

| 功能 | 参数 | 说明 | 测试覆盖 |
| --- | --- | --- | --- |
| zlib 压缩 | `-compress` | 默认开启，用于嵌入数据预处理 | 模板编译覆盖 |
| 延迟执行 | `-delay` | 配置运行时延迟秒数 | 配置/模板数据覆盖 |
| 睡眠混淆 | `-obfuscate` | 生成可选运行时代码路径 | 默认模板数据覆盖 |
| payload 变异 | `-mutate` | 生成可选运行时代码路径 | 默认模板数据覆盖 |
| 执行模式 | `-inject-mode` | 支持默认、`inject`、`earlybird` | 配置校验覆盖 |
| 旧版注入参数 | `-inject` / `-earlybird` | 自动映射到 `-inject-mode` | 配置校验覆盖 |
| 自删除标记 | `-self-delete` | 生成可选清理模板 | 模板编译覆盖 |
| indirect syscall | `-indirect-syscall` | 生成可选支持代码 | 编译测试覆盖 |
| module stomping | `-stomp-dll` | 针对指定 DLL 生成可选路径 | 编译测试覆盖 |
| 环境绑定加密 | `-env-bind` | 根据声明的环境特征派生运行时密钥 | 确定性行为测试覆盖 |
| 内存权限混淆 | `-mem-obf` | 生成可选权限切换路径 | 编译测试覆盖 |
| 技术片段选择 | `-evasion-techs` | 从 `internal/knowledge` 选择片段 | 编译测试覆盖 |

## 安装与构建

环境要求：

- Go 1.21 或更高版本
- 支持 Go 交叉编译到 `windows/amd64`

构建生成器：

```bash
go build -ldflags "-s -w" -o GoPhantom generator.go
```

运行测试：

```bash
go test ./...
```

## 使用方法

基础生成命令：

```bash
./GoPhantom -decoy ./fixtures/decoy.pdf -payload ./fixtures/payload.bin -out ./dist/loader.exe
```

`-out` 会自动补齐 `.exe` 后缀。例如传入 `./dist/loader` 时，实际输出为 `./dist/loader.exe`。

### 必需参数

| 参数 | 说明 |
| --- | --- |
| `-decoy` | 要嵌入生成 Loader 的诱饵文件路径 |
| `-payload` | 要嵌入生成 Loader 的原始 payload 字节文件 |
| `-out` | 生成的 Windows 可执行文件输出路径 |

### 可选参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-compress` | `true` | 加密前压缩嵌入数据 |
| `-delay` | `0` | 运行时延迟秒数 |
| `-obfuscate` | `false` | 包含可选睡眠混淆代码路径 |
| `-mutate` | `false` | 包含可选 payload 变异代码路径 |
| `-inject-mode` | 空 | 选择 `inject`、`earlybird` 或默认本地路径 |
| `-self-delete` | `false` | 包含可选重启后清理标记 |
| `-indirect-syscall` | `false` | 包含可选 indirect syscall 支持代码 |
| `-stomp-dll` | 空 | 为指定 DLL 包含可选 module-stomping 路径 |
| `-env-bind` | 空 | 将加密材料绑定到声明的环境特征 |
| `-mem-obf` | `false` | 包含可选内存权限切换路径 |
| `-evasion-techs` | 空 | 逗号分隔的技术 ID，如 `T001,T003` |

旧版 `-inject` 与 `-earlybird` 仍然可用，会分别映射为 `-inject-mode=inject` 和 `-inject-mode=earlybird`。

### 示例

默认模式：

```bash
./GoPhantom -decoy doc.pdf -payload payload.bin -out loader.exe
```

指定执行模式：

```bash
./GoPhantom -decoy doc.pdf -payload payload.bin -out loader.exe -inject-mode=inject
```

组合多个可选能力：

```bash
./GoPhantom \
  -decoy image.jpg \
  -payload payload.bin \
  -out advanced.exe \
  -compress \
  -obfuscate \
  -mutate \
  -inject-mode=earlybird \
  -self-delete \
  -delay 30
```

## 可复现构建

设置 `GOPHANTOM_SALT` 为 base64 编码的 16 字节值后，相同输入与相同参数会得到确定性的构建期随机选择。

```bash
export GOPHANTOM_SALT="AAAAAAAAAAAAAAAAAAAAAA=="
./GoPhantom -decoy ./fixtures/decoy.pdf -payload ./fixtures/payload.bin -out ./dist/repro.exe
```

确定性模式覆盖字符串 key、patch 变体选择、AEAD nonce，以及 env-bind 模式中的 salt 生成。未设置 `GOPHANTOM_SALT` 时，生成器会使用新鲜随机数，输出天然不可复现。

## 环境绑定模式

`-env-bind` 接受逗号分隔的 `key=value` 列表。当前支持的 key：

- `hostname`
- `domain`
- `username`
- `hostsfile`

示例：

```bash
./GoPhantom \
  -decoy ./fixtures/decoy.pdf \
  -payload ./fixtures/payload.bin \
  -out ./dist/env-bound.exe \
  -env-bind hostname=LAB-WIN11,domain=LAB
```

生成器会校验特征名，并将特征列表及期望键值集合的哈希写入模板。运行时会重新采集声明的特征值，只有派生结果匹配时才继续后续流程。

## 开发流程

推荐的本地检查：

```bash
gofmt -w generator.go generator_test.go internal/keymgr/keymgr.go internal/keymgr/keymgr_test.go internal/knowledge/techniques.go
go test ./...
```

添加新 flag 或模板能力时，建议同步更新：

1. `generator.go` 中的 `Config`
2. `registerFlags`
3. `Config.Validate`
4. `Config.Features`
5. 需要传入模板时更新 `TemplateData`
6. `generator_test.go` 中的编译测试或单元测试
7. README 中的功能矩阵

## 测试策略

测试分两层：

- 快速单元测试：覆盖配置校验、确定性随机源、env-bind 解析、输出路径规范化、模板数据构造等。
- 模板编译测试：渲染代表性 Loader 组合，并交叉编译为 `windows/amd64`，防止模板组合在编译期失效。

这对本项目很重要，因为很多回归不是普通 Go 包编译失败，而是模板渲染后才会暴露。

## 演示截图

### 生成过程

![生成过程](image/img_1.png)

### 检测效果示例

![检测效果示例](image/img_2.png)

### 执行效果

在授权测试环境中执行生成的 Loader：

- 自动释放并打开诱饵文件
- 后续逻辑在后台按配置继续执行

![执行效果](image/img.png)

## 项目结构

```text
GoPhantom/
├── generator.go              # 生成器主程序
├── generator_test.go         # 配置、模板渲染与交叉编译测试
├── build/
│   ├── go.mod.tmpl           # 临时构建模块 go.mod
│   └── go.sum                # 临时构建模块 go.sum
├── templates/
│   ├── loader.go.tmpl        # 主模板：常量、import、main
│   ├── _structs.go.tmpl      # Windows 结构体定义
│   ├── _infra.go.tmpl        # DLL 缓存、工具函数、字符串解码
│   ├── _bypass.go.tmpl       # 运行时相关模板
│   ├── _sandbox.go.tmpl      # 加权评分制环境检测
│   ├── _crypto.go.tmpl       # 解密与环境绑定密钥重建
│   ├── _execute.go.tmpl      # 执行路径模板
│   ├── _syscall.go.tmpl      # 可选 syscall 支持
│   ├── _stomping.go.tmpl     # 可选 module-stomping 路径
│   ├── _cleanup.go.tmpl      # 可选清理逻辑
│   └── _camouflage.go.tmpl   # 行为伪装相关模板
├── internal/
│   ├── keymgr/               # 密钥管理与测试
│   └── knowledge/            # 技术元数据
├── image/                    # README 演示图片
├── build.sh                  # 构建脚本
└── README.md                 # 项目文档
```

## 已知限制

- 交叉编译测试能证明生成代码可编译，但不等于在所有 Windows 版本上都完成运行时验证。
- env-bind 模式依赖运行时环境特征值与生成时声明完全一致。
- 新模板组合应保守扩展，并配套编译测试。
- 加密封装主要用于降低简单静态分析的可见性；当分析者完全控制样本和运行环境时，不应把它视为强机密保护。
- 本项目不承诺通用绕过、隐蔽或检测结果。

## 免责声明

**此工具仅限于授权的渗透测试、安全研究和教育目的。**

严禁将此工具用于任何非法活动。本项目作者不对任何因滥用或非法使用此工具导致的直接或间接后果承担责任。使用者应对自己的所有行为负责。

**使用本工具即表示您已阅读、理解并同意遵守此免责声明。**

## 支持项目

如果这个项目对您有帮助，欢迎点一个 Star 支持一下。

有问题或建议也欢迎提交 Issue 或 Pull Request。

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=watanabe-hsad/GoPhantom&type=date&legend=top-left)](https://www.star-history.com/#watanabe-hsad/GoPhantom&type=date&legend=top-left)

## 交流群

欢迎加入 QQ 群交流讨论，一起探索红队技术与工程化实践。

![QQ交流群](image/QQgroup.jpg)

## License

MIT. See [LICENSE](LICENSE).
