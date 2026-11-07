---
name: fw-analyzer
description: Binary-level firmware analyzer, single engine AxFInspector, read-only. Input is one .axf/ELF (with DWARF debug info); it answers "what did the compiler actually produce, where did the crash land, what occupies memory, how big is a function's stack frame and how deep can a call chain go". Use it for HardFault crash-address resolution (PC=0x, PC/LR registers), disassembly or machine code, function/data object size ranking (Flash/RAM usage), unused symbols, struct memory layout (member offsets, padding, bitfields), section layout and memory map, build options and ABI (FPU, soft/hard float, compiler version, architecture), absolute symbol addresses, firmware checksum (SHA256/version comparison), and stack-frame or call-chain stack-depth estimates. It assumes no specific chip, compiler or RTOS. Pure source-code questions (source-level callers, macro expansion, include dependencies, data flow, cyclomatic complexity) are out of scope: use grep or read the source instead.
---

# FwAnalyzer — firmware binary analyzer (AxFInspector)

One engine, read-only, one input: an **`.axf` (ELF + DWARF)**. It reports facts *after linking*:

- which source line a crash address maps to, including the inline chain;
- what the compiler emitted for a function;
- which symbols occupy Flash/RAM, and which static objects are never referenced;
- the real in-memory layout of a struct (padding, bitfields, member offsets);
- section layout, ABI/FPU configuration, symbol addresses, firmware hashes;
- the stack frame of any function, and the deepest stack usage of a call chain starting at any entry.

It **does not assume** Cortex-M, FreeRTOS/RTX/ThreadX, 4-byte stack words, a fixed exception frame, or any minimum stack size. Every conclusion is derived from the supplied ELF/DWARF and disassembly.

> **Relationship to grep:** prefer this skill for questions about *build artifacts*; for questions about *what the source says* (source-level callers, macros, include chains, data flow, cyclomatic complexity) this tool cannot answer — use grep / read the source. Do not stretch `--callgraph` into a source-level answer.

## Requirements

```bash
pip install pyelftools>=0.29      # required
pip install capstone>=4.0         # optional; without it --disasm falls back to a hex dump
```

- Input: an ELF32/ELF64 `.axf` (ARMCC, ARMClang or GCC output). **Keil does not need to be installed.**
- Debug-grade features (`--addr2line`, `--struct`, `--disasm --mixed`, the CFI path of stack analysis) need DWARF, i.e. the build used `-g`. Without DWARF those features report an explicit error or degrade — they never silently return a wrong answer.
- Python 3.10+. On Windows consoles set `PYTHONUTF8=1` when paths contain non-ASCII characters.

## Quick start

```powershell
python axf_inspector.py --axf firmware.axf --addr2line 0x08001234
python axf_inspector.py --axf firmware.axf --disasm main --mixed
python axf_inspector.py --axf firmware.axf --top --type func --limit 10
python axf_inspector.py --axf firmware.axf --struct demo_ctx --expand
python axf_inspector.py --axf firmware.axf --stackframe app_task
python axf_inspector.py --axf firmware.axf --stackdepth main --json
```

Every command is read-only: the `.axf`, sources and project files are never modified.

## Two transports: MCP (preferred) or CLI

The same engine is exposed two ways; MCP calls `axf_inspector.py` directly, so results cannot drift.

**MCP (preferred when the host supports it).** `mcp_server.py` is a zero-dependency stdio server with 14 tools. It caches the parsed image by (path, size, mtime), so a multi-step investigation parses DWARF once instead of once per command — on optimized images that saves seconds per query. Claude Code project-scope config ships as `.mcp.json`; run it directly with `python mcp_server.py`.

| Tool | Equivalent CLI mode |
|---|---|
| `axf_file_info` | image identity (path, size, SHA256) |
| `axf_build_info` | `--build-info` |
| `axf_symbols_top` | `--top` |
| `axf_unused` | `--unused` |
| `axf_segments` | `--segments` |
| `axf_symbol_addr` | `--symbol-addr` |
| `axf_checksum` | `--checksum` |
| `axf_addr2line` | `--addr2line` |
| `axf_disasm` | `--disasm` |
| `axf_struct` | `--struct` |
| `axf_callgraph` | `--callgraph` |
| `axf_stackframe` | `--stackframe` |
| `axf_stackdepth` | `--stackdepth` |
| `axf_audit_tasks` | `--audit-tasks` |

Every tool takes `axf` (the image path) and an optional `max_chars` for long text. Failures are MCP tool errors (`isError: true`) with stable codes: `FILE_NOT_FOUND`, `BAD_ELF`, `SYMBOL_NOT_FOUND`, `NO_SOURCE_INFO`, `FUNCTION_NOT_FOUND`, `STRUCT_NOT_FOUND`, `BAD_ARGUMENT`, `BAD_MANIFEST`, `INTERNAL`. Every tool declares all four MCP annotations (`readOnlyHint=true`, `destructiveHint=false`, `idempotentHint=true`, `openWorldHint=false`), matching the fact that the server never writes to the image, sources or project.

**CLI (fallback).** Any agent that can run shell commands uses the commands below; `SKILL.md` stays the policy layer either way (when to use, never guess the image, `-O0`/`-Og` advice, callgraph/unused caveats).

## Command reference

| Question | Command |
|---|---|
| Crash address → source line (inline chain) | `--addr2line <hex>` / `--callstack <hex>` |
| What a function compiled into | `--disasm <func> [--mixed]` |
| Largest functions/data objects | `--top [--type func\|data] [--limit N] [--region all\|ram\|flash]` |
| Static objects that look unreferenced | `--unused [--min-size N] [--include-funcs]` |
| Real struct memory layout | `--struct <name> [--expand]` |
| Static call graph (post-link direct calls) | `--callgraph <func> [--depth N]` |
| Section layout / program headers | `--segments` |
| Build options, architecture, ABI, FPU | `--build-info` |
| Absolute symbol address (variable/function) | `--symbol-addr <name>` |
| Firmware checksum (SHA256) | `--checksum [--section .text,.rodata]` |
| Single function stack frame | `--stackframe <func>` |
| Call-chain stack depth from any entry | `--stackdepth <entry>` |
| Machine-readable output | append `--json` |
| Budget audit (entry list + allocation supplied by you) | `--audit-tasks <manifest.json> --project-root <dir>` |

---

# Stack-depth estimation (generic, not RTOS-bound)

The tool does exactly one thing: **accumulate stack frames along instructions and call edges**. It does not judge your execution model, does not infer task-stack allocation units, and knows nothing about minimum-stack policies.

## Single function frame: `--stackframe <func>`

Prefers DWARF CFI rules with an SP-relative CFA (taking the maximum offset); falls back to a Thumb prologue scan (`PUSH` + `SUB SP` / `ADD SP`) when CFI is unusable. The output reports the function address, code size, prologue instructions, saved-register bytes and local-variable bytes, plus the **modelled frame size and its source**.

```powershell
python axf_inspector.py --axf firmware.axf --stackframe app_task
```

Rules:

- The value is a **model**, not a runtime peak. `alloca`/variable-length arrays, register spilling and stack-protector code change real usage.
- The frame source is labelled (CFI / prologue scan). When the two disagree, CFI wins and you are told to double-check the disassembly.
- Stack growth direction, alignment and word size are never assumed; they come from ELF attributes, DWARF and the disassembly.

## Call-chain estimate from any entry: `--stackdepth <entry>`

The entry is chosen by the caller: `main`, an interrupt service routine, an RTOS task function, a business function, or any symbol used for testing — **the tool does not care whether it is a "thread"**.

```powershell
python axf_inspector.py --axf firmware.axf --stackdepth main
python axf_inspector.py --axf firmware.axf --stackdepth uart_rx_isr --json
```

Behaviour:

- Walks the call tree from the entry symbol, accumulates frames along the deepest path, prints the tree (own frame / cumulative depth per node), and marks the deepest path.
- `--indirect-penalty <N>`: an explicit uncertainty added for every indirect edge (function pointers etc.), default 80 bytes. It is **not an upper bound**.
- `--safety-factor <F>`: multiplies the modelled bytes, default 1.5; it absorbs bounded modelling error but cannot replace missing evidence.
- `--context-bytes <N>` (legacy alias `--freertos-context`): extra context budget in bytes (exception frame, registers saved by a kernel/runtime, etc.), default 0 meaning **not included**; never inferred automatically. Bare-metal users normally keep 0 or enter the exception-entry overhead.
- Cycle detection is per path; with recursion or re-entry the true worst case is unknown and the answer must be labelled uncertain.

The tool **does not**: discover task/thread entries, derive allocation units (word/byte/`StackType_t`), apply an RTOS minimum-stack or alignment policy, or claim that a stack is "safe".

## Optional: budget audit (`--audit-tasks` manifest)

Use this only when the user **explicitly supplies the entry list and allocation budget**. The manifest is plain JSON, `schema_version=2`, and may describe any execution model (bare-metal `main`/ISR, RTOS tasks, coroutines, test stubs):

```json
{
  "allocation_policy": {
    "unit_name": "target stack allocation unit",
    "unit_bytes": 1,
    "minimum_units": 0,
    "granularity_units": 1
  },
  "context": {"bytes": 0, "evidence": "unresolved"},
  "tasks": [{"entry": "app_task", "allocated_units": 1024}]
}
```

```powershell
python axf_inspector.py --axf firmware.axf --audit-tasks my-budget.json --project-root . --json
```

The manifest is project-owned (do not write it back into the tool directory). `allocation` only supports a single decimal integer macro; expressions or conditional values are reported as evidence gaps.

Arithmetic (internally bytes):

```text
base_bytes        = modeled_bytes + context_bytes
required_bytes    = ceil(base_bytes * safety_factor)
required_units    = ceil(required_bytes / unit_bytes)
recommended_units = max(minimum_units,
                        ceil(required_units / granularity_units) * granularity_units)
allocated_bytes   = allocated_units * unit_bytes
required_ratio    = required_bytes / allocated_bytes
```

Callback-path model: the sum of frames along the path plus the complete model chain of the final function, compared against the direct-call model, taking the maximum. Paths must start at an entry and carry traceable evidence. Missing symbols and intermediate dispatch nodes must not be silently dropped.

| Status | How it must be reported |
|---|---|
| `MISSING_SYMBOL` | Manifest and firmware/optimisation disagree; cannot compute, must not count as 0 B |
| `MODEL_OVER_BUDGET` | Identified model exceeds the allocation; verify path, units and context first; not proof of an overflow |
| `INCOMPLETE` | Unresolved indirect calls, tail jumps, recursion, fallback models or configuration evidence gaps; cannot call it safe |
| `NEEDS_RUNTIME_CHECK` | Model fits, but target-device coverage is still required; not SAFE |

CLI exit code 0 only means the analysis ran. A report must list the build hash, allocation unit, allocated value, modelled bytes, context bytes, recommended units, evidence gaps and the runtime verification plan.

## Pitfalls

- Fixed recursion depth, call-site count or function-size caps silently undercount; a global `visited` set truncates shared subtrees. Per-path cycle breaking is still not a static bound for recursion or re-entry.
- CFI is unwind information, not proof of stack usage. Only an interpretable SP-relative CFA can be used directly; frame-pointer CFA, expressions, dynamic SP, branch-dependent allocation and call-site SP require reading the disassembly or the compiler's stack report.
- BL/direct call graphs miss tail calls, indirect jumps, inline assembly and runtime-loaded targets. A heuristic penalty is an explicit uncertainty, not a mathematical bound.
- Hardware FPU presence, the ABI argument convention, compiler-emitted floating-point instructions and context saved by the execution model are four different facts; trust the actual build.
- Truncating a call cycle is neither a safe upper bound nor necessarily a lower bound; prove the maximum recursion count, rewrite to iteration, or include the state space in the model.
- A runtime high-water mark covers only executed paths; fill-pattern methods are also affected by unwritten large objects, stack initialisation and sampling timing, and enabling the monitor can itself change stack usage and timing.
- The safety factor absorbs bounded modelling error; it does not replace missing entries, unknown callbacks, wrong units or unknown context.

---

# Subcommand details

## `--addr2line <hex>` / `--callstack <hex>`

Address → source location; when the address falls in an inlined function the inline chain is printed as a tree. `--callstack` is an alias for the same feature, for explicit use when investigating a crash.

```powershell
python axf_inspector.py --axf firmware.axf --addr2line 0x08001234
```

```text
0x08001234: main.c:100
  └─ inlined from: ring_buffer.h:25 (ring_buffer_push)
      └─ inlined from: uart_irq.c:80 (UART_IRQ_Handler)
```

Maximum inline expansion depth is 20 levels.

## `--disasm <func> [--mixed]`

Disassemble a function. `--mixed` interleaves source lines. Without capstone the output is a hex dump.

```powershell
python axf_inspector.py --axf firmware.axf --disasm main
python axf_inspector.py --axf firmware.axf --disasm app_task --mixed
```

## `--top [--type {func,data}] [--limit N] [--region all|ram|flash]`

Lists the largest functions or data objects in descending order.

- `--region ram` counts only writable data sections (`.data/.bss`) and is the correct entry point for memory trimming; the default `all` mixes in `.rodata` (Flash constants) and easily misleads.
- Regions are classified by section flags (`SHF_ALLOC` + `SHF_WRITE` ⇒ RAM), independent of the chip model.

```powershell
python axf_inspector.py --axf firmware.axf --top
python axf_inspector.py --axf firmware.axf --top --type data --region ram
python axf_inspector.py --axf firmware.axf --top --type func --limit 10
```

## `--unused [--min-size N] [--include-funcs]`

Candidates for "defined but never referenced" static objects: scans pointer-sized words in `SHF_ALLOC` sections, and disassembles functions to collect `BL/BLX` targets and `movw/movt`-synthesised addresses (Cortex-M function pointers carry the low bit, normalised as `addr & ~1`).

Only data objects are reported by default. Function-level dead code is off by default (function-pointer dispatch, tail calls and zero-length symbols create false positives); enable with `--include-funcs` and review by hand.

> This is a candidate list, not a "safe to delete" conclusion: debug info, linker-script symbols (`__initial_sp`, …) and unrecognised indirect jumps can all make a live symbol look unreferenced.

```powershell
python axf_inspector.py --axf firmware.axf --unused --min-size 64
python axf_inspector.py --axf firmware.axf --unused --include-funcs
```

## `--struct <name> [--expand]`

DWARF-based real memory layout of a struct/union: member offsets, types, bitfields and the total `DW_AT_byte_size`; `--expand` recurses into nested structs. Anonymous structs behind a `typedef struct {...} Foo_t;` are supported.

```powershell
python axf_inspector.py --axf firmware.axf --struct demo_ctx
python axf_inspector.py --axf firmware.axf --struct demo_ctx --expand
```

## `--callgraph <func> [--depth N]`

Tree of static call relationships (who calls it + what it calls). **Based on ELF relocations, direct calls only**:

- no function-pointer dispatch, vtables or tail calls;
- no inlined calls (present in source, gone in the binary);
- no code the linker discarded.

For "who calls this in the source", this is the wrong tool — use grep/your editor.

```powershell
python axf_inspector.py --axf firmware.axf --callgraph app_init --depth 3
```

## `--segments`

Program headers / segments: type, virtual address, physical address, file size, memory size, read/write/execute permissions.

```powershell
python axf_inspector.py --axf firmware.axf --segments
```

## `--build-info`

Toolchain, architecture, ABI, FPU/float ABI and alignment recorded in the ELF attributes.

```powershell
python axf_inspector.py --axf firmware.axf --build-info
```

## `--symbol-addr <name>`

Absolute virtual address and owning section of a symbol (function or variable).

```powershell
python axf_inspector.py --axf firmware.axf --symbol-addr demo_buffer
```

## `--checksum [--section <list>]`

SHA256 over the requested sections, for firmware version comparison. Defaults to `.text,.rodata,.data`.

```powershell
python axf_inspector.py --axf firmware.axf --checksum
python axf_inspector.py --axf firmware.axf --checksum --section .text,.rodata
```

## `--json`

Every subcommand supports it; output becomes machine-readable JSON for an agent or downstream tooling.

---

# Capability boundary

| Answers (post-link facts) | Cannot answer (source semantics) |
|---|---|
| Crash address → source line, inline chain | Who calls a function in the source (inlined/dead code included) |
| Machine code emitted for a function | Macro expansion |
| Function/data object size ranking | Include dependency graph of a `.c` |
| Section layout, memory map | Variable-level data flow (who writes x) |
| Real struct offsets/padding/bitfields | Cyclomatic complexity |
| ABI, FPU, build options | Source-level signature (DWARF covers only what was compiled) |
| Symbol addresses, firmware checksum | — |
| Stack-frame estimates, call-chain depth (model values) | Runtime peak stack; whether a stack is "safe" |

Use grep / read the source for source-level semantics. **Do not** present `--callgraph` output as source call relations, and do not delete code based on `--unused`.

---

# AI workflows

## Crash triage (HardFault / PC)

```text
1. --addr2line <PC>             → source line, inline chain
2. --disasm <that function> --mixed → actual instructions and register usage at the fault
3. --struct <related struct>    → confirm offsets/padding match expectations
4. grep the source for context when needed (this tool does not answer source semantics)
```

## Memory / size optimisation

```text
1. --top --type data --region ram   → RAM ranking (excludes .rodata noise)
2. --top --type func                → largest functions
3. --unused --min-size 64           → dead static candidates (review before deleting)
4. --segments                       → does the layout match the linker script?
```

## Stack-depth assessment

```text
1. --stackframe <suspicious function>          → single frame (CFI preferred)
2. --stackdepth <entry> --json                 → deepest path from that entry
3. pick the entry from the user's scenario: main/ISR on bare metal, a task
   function on an RTOS, and supply the context budget yourself
4. for budget audits, fill the --audit-tasks manifest and read the status fields
```

Every conclusion must state: build hash, entry, modelled bytes, context bytes, indirect penalty / safety factor, and evidence gaps. A model that fits is not "safe"; target-device coverage is still required.

## Build verification

```text
1. --build-info   → ABI / architecture / FPU match expectations
2. --segments     → section layout
3. --checksum     → firmware version matches
```

## Struct / memory questions

```text
1. --struct <name> --expand   → DWARF layout (offsets, padding, bitfields)
2. --symbol-addr <name>       → object address
3. grep the declaration to see whether this is a source mistake or an unexpected layout
```

---

# Project decoupling

- No chip, compiler, project name, directory or RTOS is hard-coded; `firmware.axf`, `app_task` and `demo_ctx` in the examples are placeholders.
- The tool only reads a built `.axf`; it does not require Keil/MDK, does not read `.uvprojx`, and does not run builds.
- The `--audit-tasks` manifest is **project-owned** (a project config directory or anywhere outside this tool); a generic template ships as `task-audit-template.json`. Do not write concrete chips, entry names or budgets back into the template.
- Tool paths in examples assume the script sits in the current directory.

# Read-only and safety

- Never modifies the `.axf`, sources, project files or linker scripts; no network access; no writes besides stdout.
- Every conclusion is traceable to its evidence (CFI/prologue scan, section flags, relocation table, DWARF DIE).

# Self-test

```powershell
python -m unittest discover -s . -p "test_*.py" -v
```

Covers stack-budget arithmetic, model boundaries, evidence handling and the MCP transport. Tests that need a real ELF build one with Keil's armclang and skip when it is absent.
