# FwAnalyzer (AxFInspector)

**Read a firmware `.axf` like a debugger would: crash addresses, machine code, memory usage, struct layout, stack depth — from one ELF file, with no IDE and no build step.**

[English](README.md) | [简体中文](README.zh-CN.md)

`axf_inspector.py` is a dependency-light Python script (one required package) that parses an ELF/DWARF firmware image produced by any ARM toolchain (ARMCC, ARMClang, GCC). It turns the build artifact into structured, machine-readable answers that a human **or an AI agent** can act on. Every command is read-only.

## What it answers

| Question | Example |
|---|---|
| A HardFault left `PC=0x08001234` — which line is it? | `--addr2line 0x08001234` (prints the inline chain too) |
| What did the compiler emit for this function? | `--disasm app_task --mixed` |
| Which functions/data objects eat the most Flash/RAM? | `--top --type func` / `--top --type data --region ram` |
| Which static objects are never referenced? | `--unused --min-size 64` |
| What is the real memory layout of this struct? | `--struct demo_ctx --expand` |
| How is the image laid out (segments/headers)? | `--segments` |
| Which ABI / FPU / compiler options was this built with? | `--build-info` |
| Where does this symbol live? | `--symbol-addr demo_buffer` |
| Are two builds identical? | `--checksum` |
| How big is this function's stack frame? How deep can this call chain get? | `--stackframe app_task` / `--stackdepth main` |

Each answer can be emitted as plain text (for humans) or `--json` (for agents/tools).

## What it is not

This is a **binary-level** analyzer. It deliberately does not do source-code analysis:

- who calls a function *in the source* (inlining, dead code, function-pointer call sites) → use grep / your editor
- macro expansion, include dependency graphs, variable data flow, cyclomatic complexity → source tooling

`--callgraph` uses the ELF relocation table and therefore only sees static direct calls after linking. It is not a source call graph.

## Requirements

```bash
pip install -r requirements.txt     # pyelftools (required), capstone (optional)
```

| Requirement | Notes |
|---|---|
| Python 3.10+ | the script uses PEP 604 type unions |
| `pyelftools>=0.29` | ELF/DWARF parsing |
| `capstone>=4.0` | optional; enables real disassembly, otherwise `--disasm` prints a hex dump |
| Firmware `.axf` built with `-g` | DWARF is required for `--addr2line`, `--struct`, `--disasm --mixed`, and the CFI path of stack analysis |

**Keil/MDK does not need to be installed.** Any ELF32/ELF64 `.axf` works.

On Windows consoles set `PYTHONUTF8=1` when paths contain non-ASCII characters.

## Build settings for analysis (recommended)

Prefer a **dedicated debug build** when you analyze firmware: high optimization changes what ends up in the `.axf`, and several answers become less faithful.

| Setting | Why it matters for this tool |
|---|---|
| `-O0` or `-Og` | keeps functions and locals visible; inlining and code motion at `-O2/-O3` hide calls and variables from `--addr2line`, `--callgraph` and `--stackframe`/`--stackdepth` |
| `-g` (DWARF) | required by `--addr2line`, `--struct`, `--disasm --mixed` and the CFI path of stack analysis |
| `-fno-inline` | optional; preserves call edges for `--callgraph` and the stack-depth model |
| `-fno-omit-frame-pointer` | optional; more reliable unwind and stack-frame evidence |
| no LTO for the analysis build | LTO merges and drops code, weakening call-graph and stack-depth results |

- Keep the normal optimized image for release, size ranking, checksum and real stack behaviour; use the analysis build for source correlation, call graph and stack estimates.
- Do not ship the analysis image, and do not compare checksums across different optimization levels.
- The tool still works on optimized images, but conclusions are weaker — always report the image hash and its build options (`--build-info`) alongside a finding.
- Flag spelling depends on the compiler (ARMCLANG/AC6 and GCC accept the forms above; older ARMCC uses its own equivalents) — set them in Keil or your build system.

## Quick start

```powershell
python axf_inspector.py --axf firmware.axf --addr2line 0x08001234
python axf_inspector.py --axf firmware.axf --disasm main --mixed
python axf_inspector.py --axf firmware.axf --top --type data --region ram
python axf_inspector.py --axf firmware.axf --unused --min-size 64
python axf_inspector.py --axf firmware.axf --struct demo_ctx --expand
python axf_inspector.py --axf firmware.axf --stackframe app_task
python axf_inspector.py --axf firmware.axf --stackdepth main --json
```

Example (`--addr2line`):

```text
0x08001234: main.c:100
  └─ inlined from: ring_buffer.h:25 (ring_buffer_push)
      └─ inlined from: uart_irq.c:80 (UART_IRQ_Handler)
```

## Command reference

```
python axf_inspector.py --axf <firmware.axf> <mode> [options]
```

| Mode | Purpose |
|---|---|
| `--addr2line HEX` | address → source file:line (inline chain expanded) |
| `--callstack HEX` | alias of `--addr2line`, named for crash investigations |
| `--disasm FUNC [--mixed]` | disassemble a function; `--mixed` interleaves source |
| `--stackframe FUNC` | one function's stack frame (CFI first, prologue scan fallback) |
| `--stackdepth ENTRY` | accumulated stack depth along the deepest call chain from `ENTRY` |
| `--top [--type func\|data] [--limit N] [--region all\|ram\|flash]` | symbol size ranking |
| `--unused [--min-size N] [--include-funcs]` | candidates for unreferenced static objects |
| `--struct NAME [--expand]` | real struct/union layout from DWARF |
| `--callgraph FUNC [--depth N]` | static call tree (direct calls only) |
| `--segments` | program headers / segment map |
| `--build-info` | toolchain, architecture, ABI, FPU, alignment |
| `--symbol-addr NAME` | absolute address and section of a symbol |
| `--checksum [--section LIST]` | SHA256 of selected sections (default `.text,.rodata,.data`) |
| `--audit-tasks MANIFEST --project-root DIR` | optional stack-budget audit against your own allocation manifest |
| `--json` | machine-readable output for every mode |
| `--indirect-penalty N` | per-indirect-edge uncertainty for `--stackdepth` (default 80 B) |
| `--safety-factor F` | model multiplier for `--stackdepth` (default 1.5) |
| `--context-bytes N` | extra context budget in bytes (legacy alias `--freertos-context`, default 0 = not included) |
| `--version`, `-h/--help` | version / usage |

## Stack-depth estimation (not RTOS-bound)

Stack analysis is a **pure instruction-level model** and makes no assumption about your execution model:

- `--stackframe FUNC` reads CFI rules with an SP-relative CFA when available, otherwise falls back to decoding the Thumb prologue (`PUSH` / `SUB SP` / `ADD SP`). It reports the modelled frame, its source, and the instruction evidence.
- `--stackdepth ENTRY` accumulates frames along the deepest path from **any** entry symbol: `main`, an ISR, an RTOS task function, a business function, or a test stub. The tool does not discover entries, infer allocation units, or apply any minimum-stack/alignment policy.
- `--context-bytes` adds an explicit budget for exception frames or registers saved by a runtime; default 0 means **not included**, and it is never inferred.
- Open-coded results are model values, not runtime peaks: `alloca`, register spilling and stack protectors change real usage. Recursion/re-entry means the true worst case is unknown and must be reported as uncertain.

If you already have an allocation budget (bare metal or RTOS), `--audit-tasks` compares it against the model using a project-owned manifest:

```powershell
python axf_inspector.py --axf firmware.axf --audit-tasks my-budget.json --project-root . --json
```

Template: [`task-audit-template.json`](task-audit-template.json) (`schema_version=2`). The arithmetic and status codes (`MISSING_SYMBOL`, `MODEL_OVER_BUDGET`, `INCOMPLETE`, `NEEDS_RUNTIME_CHECK`) are documented in [`SKILL.md`](SKILL.md).

## Using it from an AI agent

Two ways, same engine — the MCP server calls `axf_inspector.py` directly, so CLI and MCP cannot drift.

### MCP (preferred)

`mcp_server.py` is a zero-dependency stdio server exposing 14 read-only tools: `axf_file_info`, `axf_build_info`, `axf_symbols_top`, `axf_unused`, `axf_segments`, `axf_symbol_addr`, `axf_checksum`, `axf_addr2line`, `axf_disasm`, `axf_struct`, `axf_callgraph`, `axf_stackframe`, `axf_stackdepth`, `axf_audit_tasks`. The parsed image is cached by (path, size, mtime), so a multi-step investigation parses DWARF once instead of once per command.

Every tool declares all four MCP annotations — `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false` — so hosts can warn before invoking and tool directories (e.g. OpenAI) accept the manifest.

| Host | Setup |
|---|---|
| Claude Code | project `.mcp.json` is included; or `claude mcp add axf-analyzer -- python /abs/path/mcp_server.py` |
| Codex | `~/.codex/config.toml` → `[mcp_servers.axf-analyzer]` with `command = "python"`, `args = ["/abs/path/mcp_server.py"]` |
| OpenCode | `opencode.json` → `{"mcp":{"axf-analyzer":{"type":"local","command":["python","/abs/path/mcp_server.py"],"enabled":true}}}` |
| any MCP client | stdio server: run `python mcp_server.py` (JSON-RPC on stdin/stdout) |

No extra packages: the server uses only the standard library plus this analyzer.

### Skill + CLI (fallback)

`SKILL.md` is a portable skill definition (name + when-to-use description + commands + safety rules). Put this directory (or just `SKILL.md`) wherever your agent looks for skills — Claude Code `~/.claude/skills/fw-analyzer/SKILL.md`, a DSH skills directory, or any framework that accepts instruction files — then let the agent run the CLI and read `--json`. This path needs only shell access; it is the right choice when the host has no MCP support.

## Repository layout

```text
axf_inspector.py            the analyzer (single file, stdlib + pyelftools)
mcp_server.py               zero-dependency MCP stdio server (14 tools, image cache)
.mcp.json                   Claude Code project-scope MCP registration
SKILL.md                    portable agent skill definition
README.md / README.zh-CN.md this document (English) / Chinese translation
requirements.txt            pyelftools (required), capstone (optional)
task-audit-template.json    template for the optional --audit-tasks manifest
test_stack_audit.py         unit tests for stack-budget maths and evidence handling
test_mcp_server.py          MCP transport/tool tests (builds a fixture when armclang is available)
```

## Limits and troubleshooting

| Symptom | Cause / fix |
|---|---|
| `--addr2line` / `--struct` reports no debug info | the image was built without `-g`; rebuild with debug info |
| `--disasm` prints a hex dump | `capstone` is not installed (`pip install capstone>=4.0`) |
| Old ARMCC images fail to parse DWARF | DWARF 2/3 images are partially supported; confirm `-g` and try `--build-info` |
| Very large `.axf` is slow | DWARF-rich images are heavy; prefer `--top`, `--segments`, `--symbol-addr` |
| `--callgraph` misses calls | direct/static calls only — function pointers, tail calls, inlined calls and dead code are invisible |
| Inlined code hides lines or call edges | the image is optimized; analyze a dedicated `-O0`/`-Og` `-g` build (see *Build settings for analysis*) |
| `--unused` hits a live symbol | debug info, linker-script symbols and indirect references can look unused; this is a candidate list |
| Non-ASCII paths garble on Windows | `$env:PYTHONUTF8 = "1"` |

## Development

```powershell
python -m unittest discover -s . -p "test_*.py" -v
python axf_inspector.py --version
```

Tests cover stack-budget arithmetic, model boundaries, evidence handling and the MCP transport. ELF-based tests build a fixture with Keil's armclang and are skipped when it is absent.

## Design notes

- One input, no project files: the tool never reads `.uvprojx`, never runs a build and never needs Keil.
- Evidence over guesswork: every number carries its source (CFI, prologue scan, section flags, relocation table, DWARF DIE), and uncertain models are labelled as such.
- Read-only by construction: the `.axf`, sources and project files are never modified; there is no network access and no output besides stdout.
- Decoupled by design: nothing assumes a chip model, compiler, section layout or RTOS. The optional audit manifest accepts any execution model.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 wimi996123.
