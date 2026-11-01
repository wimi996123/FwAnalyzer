# FwAnalyzer (AxFInspector)

**像调试器一样读固件 `.axf`：崩溃地址、机器码、内存占用、结构体布局、栈深度——只用一个 ELF 文件，不需要 IDE，也不需要重新构建。**

[English](README.md) | 简体中文

`axf_inspector.py` 是一个依赖极少的 Python 脚本（只有一个必装包），解析任意 ARM 工具链（ARMCC、ARMClang、GCC）产出的 ELF/DWARF 固件镜像，把构建产物变成结构化的、人和 AI agent 都能直接使用的答案。所有命令都是只读的。

## 它能回答什么

| 问题 | 示例 |
|---|---|
| HardFault 留下的 `PC=0x08001234` 对应哪一行？ | `--addr2line 0x08001234`（同时展开内联链） |
| 这个函数被编译成了什么指令？ | `--disasm app_task --mixed` |
| 哪些函数/数据对象最占 Flash/RAM？ | `--top --type func` / `--top --type data --region ram` |
| 哪些静态对象没人引用？ | `--unused --min-size 64` |
| 这个结构体在内存里的真实布局？ | `--struct demo_ctx --expand` |
| 镜像的段/程序头布局？ | `--segments` |
| 这份固件用什么 ABI / FPU / 编译选项构建的？ | `--build-info` |
| 这个符号在哪里？ | `--symbol-addr demo_buffer` |
| 两次构建是否一致？ | `--checksum` |
| 这个函数栈帧多大？这条调用链最深能到多少？ | `--stackframe app_task` / `--stackdepth main` |

所有结果都可以输出为人类可读的文本，或 `--json`（给 agent / 工具消费）。

## 它不是什么

这是一个**二进制级**分析器，刻意不做源码分析：

- "源码里谁调用了这个函数"（内联展开、死代码、函数指针调用点）→ 用 grep / 编辑器
- 宏展开、include 依赖图、变量数据流、圈复杂度 → 用源码工具

`--callgraph` 基于 ELF 重定位表，只能看到链接后的静态直接调用，不是源码调用图。

## 环境要求

```bash
pip install -r requirements.txt     # pyelftools（必装）、capstone（可选）
```

| 要求 | 说明 |
|---|---|
| Python 3.10+ | 脚本使用了 PEP 604 类型联合语法 |
| `pyelftools>=0.29` | ELF/DWARF 解析 |
| `capstone>=4.0` | 可选；用于真实反汇编，缺失时 `--disasm` 输出十六进制 dump |
| 带 `-g` 构建的固件 `.axf` | `--addr2line`、`--struct`、`--disasm --mixed` 以及栈分析的 CFI 路径需要 DWARF |

**不需要安装 Keil/MDK**，任意 ELF32/ELF64 的 `.axf` 都可以。

Windows 控制台下路径含非 ASCII 字符时，建议设置 `PYTHONUTF8=1`。

## 分析用构建建议

分析固件时建议使用**专门的调试构建**：高优化等级会改变最终进入 `.axf` 的内容，部分结论会因此失真。

| 设置 | 对本工具的影响 |
|---|---|
| `-O0` 或 `-Og` | 保留函数与局部变量；`-O2/-O3` 的内联和代码搬移会让 `--addr2line`、`--callgraph`、`--stackframe`/`--stackdepth` 看不到调用与变量 |
| `-g`（DWARF） | `--addr2line`、`--struct`、`--disasm --mixed` 以及栈分析的 CFI 路径必需 |
| `-fno-inline` | 可选；保留调用边，利于 `--callgraph` 与栈深度模型 |
| `-fno-omit-frame-pointer` | 可选；展开与栈帧证据更可靠 |
| 分析构建不要开 LTO | LTO 会合并、删除代码，削弱调用图与栈深度结果 |

- 发布、体积排行、校验和与真实栈行为仍用正常的优化镜像；源码关联、调用图和栈估算用分析构建。
- 不要把分析镜像发出去，也不要在不同优化等级之间比较校验和。
- 工具在优化镜像上仍可用，但结论更弱——报告结论时必须同时给出镜像哈希与构建选项（`--build-info`）。
- 具体开关名随编译器而定（ARMCLANG/AC6 与 GCC 支持上面的写法，旧版 ARMCC 有对应选项）——在 Keil 或构建系统里设置等价项。

## 快速开始

```powershell
python axf_inspector.py --axf firmware.axf --addr2line 0x08001234
python axf_inspector.py --axf firmware.axf --disasm main --mixed
python axf_inspector.py --axf firmware.axf --top --type data --region ram
python axf_inspector.py --axf firmware.axf --unused --min-size 64
python axf_inspector.py --axf firmware.axf --struct demo_ctx --expand
python axf_inspector.py --axf firmware.axf --stackframe app_task
python axf_inspector.py --axf firmware.axf --stackdepth main --json
```

`--addr2line` 输出示例：

```text
0x08001234: main.c:100
  └─ inlined from: ring_buffer.h:25 (ring_buffer_push)
      └─ inlined from: uart_irq.c:80 (UART_IRQ_Handler)
```

## 命令参考

```
python axf_inspector.py --axf <firmware.axf> <mode> [options]
```

| 模式 | 用途 |
|---|---|
| `--addr2line HEX` | 地址 → 源码文件:行号（展开内联链） |
| `--callstack HEX` | `--addr2line` 的别名，便于崩溃排查时显式使用 |
| `--disasm FUNC [--mixed]` | 反汇编函数；`--mixed` 混合显示源码行 |
| `--stackframe FUNC` | 单函数栈帧（优先 CFI，回退前言扫描） |
| `--stackdepth ENTRY` | 从 `ENTRY` 出发的最深调用链累计栈深度 |
| `--top [--type func\|data] [--limit N] [--region all\|ram\|flash]` | 符号大小排行 |
| `--unused [--min-size N] [--include-funcs]` | 疑似未引用静态对象候选 |
| `--struct NAME [--expand]` | 基于 DWARF 的真实结构体/联合体布局 |
| `--callgraph FUNC [--depth N]` | 静态调用树（仅直接调用） |
| `--segments` | 程序头 / 段布局 |
| `--build-info` | 工具链、架构、ABI、FPU、对齐 |
| `--symbol-addr NAME` | 符号的绝对地址与所在段 |
| `--checksum [--section LIST]` | 指定段的 SHA256（默认 `.text,.rodata,.data`） |
| `--audit-tasks MANIFEST --project-root DIR` | 可选的栈预算核对（清单由项目提供） |
| `--json` | 所有模式都支持机器可读输出 |
| `--indirect-penalty N` | `--stackdepth` 的每次间接调用不确定量（默认 80 字节） |
| `--safety-factor F` | `--stackdepth` 的模型安全系数（默认 1.5） |
| `--context-bytes N` | 额外上下文字节预算（历史别名 `--freertos-context`，默认 0 = 未计入） |
| `--version`、`-h/--help` | 版本 / 用法 |

## 栈深度估算（不绑定 RTOS）

栈分析是**纯指令级模型**，不对执行模型做任何假设：

- `--stackframe FUNC`：优先读取带 SP 相对 CFA 的 CFI 规则，否则回退解码 Thumb 前言（`PUSH` / `SUB SP` / `ADD SP`）。输出模型帧大小、来源和指令证据。
- `--stackdepth ENTRY`：从**任意**入口符号累加最深路径上的帧——`main`、中断服务函数、RTOS 任务函数、业务函数或测试桩都可以。工具不会自动发现入口、不推算分配单位、不套用任何最小栈/对齐策略。
- `--context-bytes`：为异常帧或运行时保存的寄存器显式增加预算；默认 0 表示**未计入**，且绝不自动推断。
- 结果是模型值，不是运行时峰值：`alloca`、寄存器溢出、栈保护都会改变真实用量。存在递归/重入时真实最坏情况未知，必须标注为不确定。

如果已有分配预算（裸机或 RTOS 均可），可以用 `--audit-tasks` 把模型与项目自带的清单对比：

```powershell
python axf_inspector.py --axf firmware.axf --audit-tasks my-budget.json --project-root . --json
```

模板见 [`task-audit-template.json`](task-audit-template.json)（`schema_version=2`）；计算公式与状态码（`MISSING_SYMBOL`、`MODEL_OVER_BUDGET`、`INCOMPLETE`、`NEEDS_RUNTIME_CHECK`）见 [`SKILL.md`](SKILL.md)。

## 给 AI agent 使用

两种方式，同一个引擎——MCP 服务器直接调用 `axf_inspector.py`，所以 CLI 与 MCP 的结果不会分叉。

### MCP（推荐）

`mcp_server.py` 是零依赖的 stdio 服务器，暴露 14 个只读工具：`axf_file_info`、`axf_build_info`、`axf_symbols_top`、`axf_unused`、`axf_segments`、`axf_symbol_addr`、`axf_checksum`、`axf_addr2line`、`axf_disasm`、`axf_struct`、`axf_callgraph`、`axf_stackframe`、`axf_stackdepth`、`axf_audit_tasks`。解析结果按 (路径, 大小, mtime) 缓存，一次多步调查只解析一遍 DWARF。

| 宿主 | 配置 |
|---|---|
| Claude Code | 仓库自带 `.mcp.json`；或 `claude mcp add axf-analyzer -- python /abs/path/mcp_server.py` |
| Codex | `~/.codex/config.toml` → `[mcp_servers.axf-analyzer]`，`command = "python"`、`args = ["/abs/path/mcp_server.py"]` |
| OpenCode | `opencode.json` → `{"mcp":{"axf-analyzer":{"type":"local","command":["python","/abs/path/mcp_server.py"],"enabled":true}}}` |
| 任意 MCP 客户端 | stdio 服务器：运行 `python mcp_server.py`（stdin/stdout 上的 JSON-RPC） |

不需要额外依赖：服务器只用标准库 + 本分析器。

### Skill + CLI（兜底）

`SKILL.md` 是便携的 skill 定义（名称 + 何时使用 + 命令 + 安全规则）。把本目录（或仅 `SKILL.md`）放到 agent 读取技能的位置——Claude Code 的 `~/.claude/skills/fw-analyzer/SKILL.md`、DSH 的 skills 目录，或任何接受指令文件的框架——然后让 agent 运行 CLI 并读取 `--json`。这条路径只需要 shell 权限，适合不支持 MCP 的宿主。

## 仓库结构

```text
axf_inspector.py            分析器（单文件，stdlib + pyelftools）
mcp_server.py               零依赖 MCP stdio 服务器（14 个工具，带镜像缓存）
.mcp.json                   Claude Code 项目级 MCP 注册
SKILL.md                    便携的 agent 技能定义
README.md / README.zh-CN.md 英文 / 中文说明
requirements.txt            pyelftools（必装）、capstone（可选）
task-audit-template.json    可选 --audit-tasks 清单模板
test_stack_audit.py         栈预算计算与证据处理的单元测试
test_mcp_server.py          MCP 传输/工具测试（有 armclang 时构建 fixture）
```

## 限制与排查

| 现象 | 原因 / 处理 |
|---|---|
| `--addr2line` / `--struct` 提示没有调试信息 | 镜像未用 `-g` 构建；带调试信息重新编译 |
| `--disasm` 输出十六进制 dump | 未安装 `capstone`（`pip install capstone>=4.0`） |
| 旧 ARMCC 镜像 DWARF 解析失败 | DWARF 2/3 仅部分支持；确认 `-g`，并先用 `--build-info` 检查 |
| 大 `.axf` 很慢 | DWARF 丰富的镜像较重；优先用 `--top`、`--segments`、`--symbol-addr` |
| `--callgraph` 漏调用 | 仅覆盖直接/静态调用；函数指针、尾调用、内联调用和死代码不可见 |
| 内联导致行号/调用边缺失 | 镜像被优化；改用 `-O0`/`-Og` + `-g` 的分析构建（见“分析用构建建议”） |
| `--unused` 命中在用符号 | 调试信息、链接脚本符号、间接引用都会造成误判；它只是候选列表 |
| Windows 非 ASCII 路径乱码 | `$env:PYTHONUTF8 = "1"` |

## 开发与测试

```powershell
python -m unittest discover -s . -p "test_*.py" -v
python axf_inspector.py --version
```

测试覆盖栈预算计算、模型边界、证据处理与 MCP 传输；依赖 ELF 的测试会用 Keil armclang 构建 fixture，没有 armclang 时自动跳过。

## 设计说明

- 单一输入、不碰工程文件：不读 `.uvprojx`、不执行构建、不需要 Keil。
- 证据优先：每个数字都标注来源（CFI、前言扫描、节属性、重定位表、DWARF DIE），不确定的模型会明确标注。
- 天生只读：不修改 `.axf`、源码与工程文件；无网络访问；除 stdout 外无输出。
- 参数化解耦：不假设芯片型号、编译器、段布局或 RTOS；可选的审计清单接受任意执行模型。

## 许可证

MIT——见 [LICENSE](LICENSE)。Copyright (c) 2026 wimi996123。
