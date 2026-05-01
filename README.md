# GoPhantom

[![Go](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://go.dev/)
[![Target](https://img.shields.io/badge/target-windows%2Famd64-blue.svg)](https://learn.microsoft.com/windows/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Go 语言 Windows Loader 生成器。模板化构建，参数驱动，面向授权红队演练与防御验证。

> 仅限自有环境、授权实验室或书面授权的安全评估使用。

---

## 概览

GoPhantom 将 payload 与诱饵文件打包为 `windows/amd64` 可执行文件。生成器在 macOS / Linux / Windows 上交叉编译，输出的 Loader 在目标 Windows 系统上运行。

核心设计：

- 所有变体通过 CLI flag 控制，无需手工改模板
- 每次构建自动注入多态代码，默认产生不同的文件哈希；设置 `GOPHANTOM_SALT` 可切换为确定性构建
- 模板组合均有交叉编译回归测试覆盖

---

## 功能

### 加密与混淆

| 能力 | 参数 | 说明 |
|---|---|---|
| AES-256-GCM 加密 | 默认 | Argon2id 派生密钥，XOR + zlib + AEAD 三层封装 |
| ChaCha20-Poly1305 | `-env-bind` | 环境绑定模式下自动切换 |
| 字符串 XOR 编码 | 自动 | 所有敏感 API / DLL 名编译时编码，运行时解码 |
| AMSI patch 多态 | 自动 | 每次构建随机选择等效 patch 字节 |
| 多态代码注入 | 自动 | 3-7 个随机垃圾函数，改变控制流图与文件哈希 |
| Garble 编译期混淆 | `-garble` | 控制流扁平化、符号重命名、字符串字面量加密（需 Go 1.26+） |

### 执行与注入

| 能力 | 参数 | 说明 |
|---|---|---|
| 本地线程执行 | 默认 | VirtualAlloc → 写入 → VirtualProtect → CreateThread |
| 远程线程注入 | `-inject-mode=inject` | 目标进程 VirtualAllocEx + CreateRemoteThread |
| Early Bird APC | `-inject-mode=earlybird` | 挂起进程 + NtQueueApcThreadEx |
| Module Stomping | `-stomp-dll` | 覆写合法 DLL .text 段，MEM_IMAGE 伪装，自动回退候选 DLL |
| 回调执行 | 自动回退 | EnumChildWindows 回调作为备选执行路径 |

### 防御绕过

| 能力 | 参数 | 说明 |
|---|---|---|
| NTDLL 脱钩 | 自动 | 从磁盘读取干净 ntdll 覆盖内存 .text 段 |
| ETW 禁用 | 自动 | patch EtwEventWrite + NtTraceEvent |
| AMSI 禁用 | 自动 | patch AmsiScanBuffer 入口 |
| Indirect Syscall | `-indirect-syscall` | Hell's Gate / Halo's Gate + ntdll gadget 间接调用 |
| 内存权限混淆 | `-mem-obf` | RW → NoAccess → RX 三步翻转，打破 W→X 检测模式 |
| 睡眠混淆 | `-obfuscate` | sleep 期间 XOR 加密 shellcode 内存 |
| 环境绑定 | `-env-bind` | 运行时校验主机特征，非目标环境静默退出 |
| 反沙箱 | 自动 | 加权评分制环境检测（CPU / 内存 / 磁盘 / 调试器 / VM） |

### 可选技术片段 (`-evasion-techs`)

| ID | 名称 | 类别 |
|---|---|---|
| T001 | API Hashing (djb2) | API 混淆 |
| T002 | 双重 XOR 字符串混淆 | 字符串防御 |
| T003 | Direct Syscall 解析 | Hook 绕过 |
| T004 | Sleep 内存加密 | 内存规避 |
| T005 | 环境指纹校验 | 沙箱检测 |
| T006 | 硬件断点 AMSI Bypass（VEH + DR0） | Hook 绕过 |
| T007 | NtTraceControl ETW Blind | Hook 绕过 |

---

## 快速开始

### 环境要求

- Go 1.21+（基础功能）
- Go 1.26+（仅 `-garble` 需要）
- 支持交叉编译到 `windows/amd64`

### 构建与使用

```bash
# 构建生成器
go build -o GoPhantom .

# 基础生成
./GoPhantom -decoy doc.pdf -payload beacon.bin -out loader.exe

# 完整能力组合
./GoPhantom \
  -decoy doc.pdf \
  -payload beacon.bin \
  -out loader.exe \
  -indirect-syscall \
  -stomp-dll winhttp.dll \
  -mem-obf \
  -obfuscate \
  -mutate \
  -evasion-techs=T001,T003,T006,T007 \
  -env-bind hostname=TARGET-PC,domain=CORP \
  -delay 15

# 启用 Garble（需 Go 1.26+ 和 garble）
go install mvdan.cc/garble@latest
./GoPhantom -decoy doc.pdf -payload beacon.bin -out loader.exe -garble
```

`-out` 自动补齐 `.exe` 后缀。

---

## 参数

### 必需

| 参数 | 说明 |
|---|---|
| `-decoy` | 诱饵文件路径 |
| `-payload` | 原始 shellcode 文件路径 |
| `-out` | 输出可执行文件路径 |

### 可选

| 参数 | 默认 | 说明 |
|---|---|---|
| `-compress` | `true` | zlib 压缩嵌入数据 |
| `-delay` | `0` | 运行时延迟（秒） |
| `-obfuscate` | `false` | 睡眠期间内存加密 |
| `-mutate` | `false` | shellcode NOP 变异 |
| `-inject-mode` | 空 | `inject` / `earlybird` / 默认本地线程 |
| `-self-delete` | `false` | 重启时自删除 |
| `-indirect-syscall` | `false` | Indirect Syscall 引擎（Hell's Gate / Halo's Gate） |
| `-stomp-dll` | 空 | Module Stomping 牺牲 DLL（自动回退候选列表） |
| `-env-bind` | 空 | 环境绑定 `key=value`（hostname / domain / username / hostsfile） |
| `-mem-obf` | `false` | 三步内存权限翻转 |
| `-evasion-techs` | 空 | 技术片段 ID，如 `T001,T003,T006,T007` |
| `-garble` | `false` | Garble 编译期混淆（需 Go 1.26+，`go install mvdan.cc/garble@latest`） |

---

## 环境绑定

将加密密钥绑定到目标环境特征。运行时重新采集特征值，不匹配则静默退出。

```bash
./GoPhantom \
  -decoy doc.pdf -payload beacon.bin -out loader.exe \
  -env-bind hostname=DC01,domain=CORP.LOCAL
```

支持的特征：`hostname`、`domain`、`username`、`hostsfile`

---

## 确定性构建

```bash
export GOPHANTOM_SALT="AAAAAAAAAAAAAAAAAAAAAA=="
./GoPhantom -decoy doc.pdf -payload beacon.bin -out loader.exe
```

设置相同 `GOPHANTOM_SALT` 后，生成阶段的随机材料会稳定派生：字符串 key、AMSI patch 选择、AEAD nonce、env-bind salt、多态函数生成等会保持一致。

注意：Go 链接器的 build id、临时构建路径和工具链细节可能导致最终 exe 不是 bit-for-bit 完全一致。因此这里承诺的是生成阶段随机材料可复现，而不是最终二进制哈希必然一致。

`-garble` 与确定性构建兼容：设置 `GOPHANTOM_SALT` 时，garble seed 从 SALT 派生；未设置时使用随机 seed。

---

## 架构

```text
输入文件 + CLI 参数
       │
       ▼
  generator.go
  ├─ 参数校验
  ├─ 密钥派生 (Argon2id / ChaCha20)
  ├─ 资产加密 (AES-GCM / XChaCha20-Poly1305)
  ├─ 多态代码生成
  ├─ 模板渲染 (Go text/template)
  └─ 交叉编译 (go build / garble build)
       │
       ▼
  loader.exe (windows/amd64)
```

### 项目结构

```text
GoPhantom/
├── generator.go                # 生成器入口：CLI、校验、加密、模板渲染、编译
├── generator_test.go           # 配置校验 + 模板编译回归测试（含 T001-T007 组合）
├── build/
│   ├── go.mod.tmpl             # 临时构建模块
│   └── go.sum
├── templates/
│   ├── loader.go.tmpl          # 主模板：常量、import、main、多态函数
│   ├── _structs.go.tmpl        # Windows PE / API 结构体
│   ├── _infra.go.tmpl          # DLL 缓存、字符串解码、工具函数
│   ├── _bypass.go.tmpl         # NTDLL 脱钩、ETW/AMSI patch
│   ├── _sandbox.go.tmpl        # 加权评分制反沙箱
│   ├── _crypto.go.tmpl         # AES-GCM / ChaCha20 解密 + env-bind 密钥重建
│   ├── _execute.go.tmpl        # 执行路径 + 内存权限混淆
│   ├── _syscall.go.tmpl        # Indirect Syscall 引擎（Hell's Gate / Halo's Gate）
│   ├── _stomping.go.tmpl       # Module Stomping（智能 DLL 回退选择）
│   ├── _evasion.go.tmpl        # 用户选择的技术片段入口
│   ├── _camouflage.go.tmpl     # 行为伪装 + IAT 填充
│   └── _cleanup.go.tmpl        # 自删除逻辑
├── internal/
│   ├── keymgr/                 # 密钥派生 + 确定性构建支持
│   └── knowledge/              # Evasion 技术元数据 (T001-T007)
└── image/                      # 文档截图
```

---

## 测试

```bash
go test ./...
```

两层测试策略：

- 单元测试：配置校验、确定性随机源、env-bind 解析、模板数据构造
- 编译测试：渲染代表性模板组合（含 T001-T007 全量组合）→ 交叉编译 `windows/amd64`

---

## 开发

添加新功能的检查清单：

1. `Config` 结构体 + `registerFlags`
2. `Validate` + `Features`
3. `TemplateData` + 对应模板
4. `generator_test.go` 编译测试
5. README 功能矩阵

```bash
gofmt -w generator.go generator_test.go internal/keymgr/keymgr.go internal/knowledge/techniques.go
go test ./...
```

---

## 截图

| 生成过程 | 检测效果 | 执行效果 |
|---|---|---|
| ![](image/img_1.png) | ![](image/img_2.png) | ![](image/img.png) |

---

## 已知限制

- 编译测试不等于运行时验证，不覆盖所有 Windows 版本
- env-bind 要求运行时特征值与生成时声明完全一致
- 加密封装降低简单静态分析可见性，不构成强机密保护
- 不承诺通用绕过或特定检测结果

---

## 免责声明

本工具仅限授权渗透测试、安全研究和教育用途。严禁用于非法活动。作者不对滥用导致的任何后果承担责任。使用即表示同意。

---

## 社区

[![Star History](https://api.star-history.com/svg?repos=watanabe-hsad/GoPhantom&type=date&legend=top-left)](https://www.star-history.com/#watanabe-hsad/GoPhantom&type=date&legend=top-left)

QQ 交流群：

![QQ](image/QQgroup.jpg)

Issue 和 Pull Request 随时欢迎。

## License

MIT. See [LICENSE](LICENSE).
