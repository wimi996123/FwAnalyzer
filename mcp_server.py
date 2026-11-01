"""Thin MCP (Model Context Protocol) wrapper around axf_inspector.py.

Zero dependencies beyond the script itself: this module imports the analyzer and
exposes its read-only queries as MCP tools over stdio JSON-RPC. It does not
shell out and it does not re-implement anything — axf_inspector.py stays the
single source of truth, so CLI and MCP results cannot drift apart.

Run it with::

    python mcp_server.py

Design notes:

* One ELF is cached by (absolute path, size, mtime); switching files evicts it.
  This is the main reason an MCP server exists here: a multi-step investigation
  (addr2line -> disasm -> struct -> stackframe) parses DWARF once instead of
  once per invocation.
* Every tool accepts `axf` (the firmware path) plus its own arguments, and an
  optional `max_chars` that truncates long text output (default 20000).
* Tools are read-only. The server never writes to the ELF, sources or project.
"""
from __future__ import annotations

import hashlib
import json
import sys
import traceback
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Callable

import axf_inspector as core

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "axf-analyzer"
SERVER_VERSION = "1.0.0"
DEFAULT_MAX_CHARS = 20000
MAX_MAX_CHARS = 200000

# --------------------------------------------------------------------------- #
# Errors and ELF cache
# --------------------------------------------------------------------------- #


class ToolError(Exception):
    """A tool-level failure with a stable code (never crashes the server)."""

    def __init__(self, code: str, message: str, details: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


_CACHE: dict[str, Any] = {"key": None, "analyzer": None}


def _open_analyzer(axf: Any) -> tuple[Any, Path]:
    """Return a cached ELFAnalyzer for `axf`, reopening only when the file changes."""
    if not isinstance(axf, str) or axf.strip() == "":
        raise ToolError("BAD_ARGUMENT", "`axf` must be the path to a .axf/ELF file")
    path = Path(axf).expanduser().resolve()
    if not path.exists():
        raise ToolError("FILE_NOT_FOUND", f"no such file: {path}")
    if not path.is_file():
        raise ToolError("FILE_NOT_FOUND", f"not a regular file: {path}")
    stat = path.stat()
    key = (str(path), stat.st_size, stat.st_mtime_ns)
    if _CACHE["key"] != key:
        # Drop the old analyzer before parsing another image (bounded memory).
        _CACHE["key"] = None
        _CACHE["analyzer"] = None
        try:
            analyzer = core.ELFAnalyzer(str(path))
        except Exception as error:  # noqa: BLE001 - reported as a tool error
            raise ToolError("BAD_ELF", f"cannot parse ELF/DWARF: {error}") from error
        _CACHE.update(key=key, analyzer=analyzer)
    return _CACHE["analyzer"], path


# --------------------------------------------------------------------------- #
# Argument helpers
# --------------------------------------------------------------------------- #


def _max_chars(args: dict[str, Any]) -> int:
    value = args.get("max_chars", DEFAULT_MAX_CHARS)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ToolError("BAD_ARGUMENT", "`max_chars` must be a positive integer")
    return min(value, MAX_MAX_CHARS)


def _text(value: Any, limit: int) -> str:
    """Str-ify and truncate a possibly large text result."""
    text = value if isinstance(value, str) else str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars; raise max_chars for more]"


def _string(args: dict[str, Any], name: str) -> str:
    value = args.get(name)
    if not isinstance(value, str) or value.strip() == "":
        raise ToolError("BAD_ARGUMENT", f"`{name}` must be a non-empty string")
    return value


def _int(args: dict[str, Any], name: str, default: int, *, minimum: int = 0) -> int:
    value = args.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ToolError("BAD_ARGUMENT", f"`{name}` must be an integer >= {minimum}")
    return value


def _number(args: dict[str, Any], name: str, default: float) -> float:
    value = args.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 1:
        raise ToolError("BAD_ARGUMENT", f"`{name}` must be a number >= 1")
    return float(value)


def _parse_address(value: Any) -> int:
    if isinstance(value, bool):
        raise ToolError("BAD_ARGUMENT", "`address` must be a hexadecimal address")
    if isinstance(value, int):
        if value < 0:
            raise ToolError("BAD_ARGUMENT", "`address` must be non-negative")
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        try:
            return int(text, 16) if not text.startswith("0x") else int(text, 16)
        except ValueError as error:
            raise ToolError("BAD_ARGUMENT", f"invalid address: {value!r}") from error
    raise ToolError("BAD_ARGUMENT", "`address` must be a string like 0x08001234 or an integer")


def _as_dict(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, list):
        return [_as_dict(item) for item in value]
    if isinstance(value, dict):
        return {key: _as_dict(item) for key, item in value.items()}
    return value


def _node_dict(node: Any) -> dict[str, Any]:
    """Serialize a StackDepthNode tree (cycles are not possible after analysis)."""
    return {
        "function": node.func_name,
        "address": f"0x{node.address:08X}",
        "own_frame": node.own_frame,
        "cumulative_depth": node.cumulative_depth,
        "indirect_count": node.indirect_count,
        "total_indirect_count": node.total_indirect_count,
        "is_leaf": node.is_leaf,
        "is_cycle": node.is_cycle,
        "frame_source": node.frame_source,
        "children": [_node_dict(child) for child in node.children],
    }


def _file_sha256(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #


def tool_file_info(args: dict[str, Any]) -> dict[str, Any]:
    _, path = _open_analyzer(_string(args, "axf"))
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": _file_sha256(path),
        "note": "quote this hash with any finding: conclusions are only valid for this exact image",
    }


def tool_build_info(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    info = analyzer.get_build_info()
    info["axf"] = str(path)
    return info


def tool_symbols_top(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    kind = args.get("kind", "all")
    region = args.get("region", "all")
    if kind not in ("all", "func", "data"):
        raise ToolError("BAD_ARGUMENT", "`kind` must be one of: all, func, data")
    if region not in ("all", "ram", "flash"):
        raise ToolError("BAD_ARGUMENT", "`region` must be one of: all, ram, flash")
    limit = _int(args, "limit", 20, minimum=1)
    symbols = analyzer.get_symbols_sorted_by_size(
        st_type=None if kind == "all" else kind,
        region=None if region == "all" else region,
    )
    total = sum(symbol.size for symbol in symbols)
    shown = symbols[:limit]
    return {
        "axf": str(path),
        "kind": kind,
        "region": region,
        "total_symbols": len(symbols),
        "total_size": total,
        "truncated": len(symbols) > len(shown),
        "symbols": [
            {
                "rank": index + 1,
                "name": symbol.name,
                "size": symbol.size,
                "type": symbol.st_type,
                "section": symbol.section,
                "region": symbol.region,
            }
            for index, symbol in enumerate(shown)
        ],
    }


def tool_unused(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    include_funcs = bool(args.get("include_funcs", False))
    limit = _int(args, "limit", 20, minimum=1)
    min_size = _int(args, "min_size", 0)
    symbols = analyzer.get_unused_symbols(min_size=min_size, include_funcs=include_funcs)
    shown = symbols[:limit]
    return {
        "axf": str(path),
        "include_funcs": include_funcs,
        "min_size": min_size,
        "candidates": len(symbols),
        "truncated": len(symbols) > len(shown),
        "symbols": [
            {"name": symbol.name, "size": symbol.size, "type": symbol.st_type,
             "region": symbol.region, "address": f"0x{symbol.address:08X}"}
            for symbol in shown
        ],
        "warning": "candidate list, not a safe-to-delete conclusion; debug/linker/indirect references can look unused",
    }


def tool_segments(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    segments = analyzer.get_segments()
    return {
        "axf": str(path),
        "segments": [
            {"type": segment.seg_type, "vaddr": f"0x{segment.vaddr:08X}",
             "paddr": f"0x{segment.paddr:08X}", "file_size": segment.file_size,
             "mem_size": segment.mem_size, "flags": segment.flags}
            for segment in segments
        ],
    }


def tool_symbol_addr(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    name = _string(args, "name")
    symbol = analyzer.get_symbol_addr(name)
    if symbol is None:
        raise ToolError("SYMBOL_NOT_FOUND", f"symbol not found: {name}")
    return {
        "axf": str(path),
        "name": symbol.name,
        "address": f"0x{symbol.address:08X}",
        "size": symbol.size,
        "type": symbol.st_type,
        "section": symbol.section,
    }


def tool_checksum(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    sections = args.get("sections")
    if sections is not None and not (
        isinstance(sections, list) and all(isinstance(item, str) and item for item in sections)
    ):
        raise ToolError("BAD_ARGUMENT", "`sections` must be a list of section names, e.g. [\".text\", \".rodata\"]")
    return {"axf": str(path), "sha256": analyzer.get_checksum(sections=sections)}


def tool_addr2line(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    address = _parse_address(args.get("address"))
    frames = analyzer.addr2line(address)
    if not frames:
        raise ToolError("NO_SOURCE_INFO", f"no DWARF line information for 0x{address:08X} (was the image built with -g?)")
    return {
        "axf": str(path),
        "address": f"0x{address:08X}",
        "frames": [
            {"file": frame.file, "line": frame.line, "column": frame.column, "function": frame.function}
            for frame in frames
        ],
    }


def tool_disasm(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    limit = _max_chars(args)
    function = _string(args, "function")
    text = analyzer.disassemble_function(function, mixed=bool(args.get("mixed", False)))
    return {"axf": str(path), "function": function, "mixed": bool(args.get("mixed", False)),
            "text": _text(text, limit)}


def tool_struct(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    name = _string(args, "name")
    expand = bool(args.get("expand", False))
    members = analyzer.get_struct_layout(name, expand=expand)
    total = analyzer.get_struct_byte_size(name)
    if not members and total == 0:
        raise ToolError("STRUCT_NOT_FOUND", f"struct/union not found in DWARF: {name}")
    return {
        "axf": str(path),
        "name": name,
        "size": total,
        "members": [
            {
                "name": member.name,
                "type": member.type_name,
                "offset": member.offset,
                "size": member.size,
                **({"bit_offset": member.bit_offset, "bit_size": member.bit_size}
                   if member.bit_size > 0 else {}),
                **({"children": [{"name": child.name, "type": child.type_name,
                                 "offset": child.offset, "size": child.size}
                                for child in member.children]} if member.children else {}),
            }
            for member in members
        ],
    }


def tool_callgraph(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    limit = _max_chars(args)
    function = _string(args, "function")
    depth = _int(args, "depth", 2, minimum=1)
    text = analyzer.get_callgraph(function, depth=depth)
    return {"axf": str(path), "function": function, "depth": depth,
            "text": _text(text, limit),
            "warning": "ELF relocation table only: direct calls; function pointers, tail calls, inlined calls and dead code are invisible"}


def tool_stackframe(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    function = _string(args, "function")
    info = analyzer.analyze_stackframe(function)
    if info is None:
        raise ToolError("FUNCTION_NOT_FOUND", f"function not found: {function}")
    return {
        "axf": str(path),
        "name": info.name,
        "address": f"0x{info.address:08X}",
        "code_size": info.code_size,
        "is_thumb": info.is_thumb,
        "push_bytes": info.push_bytes,
        "push_regs": info.push_regs,
        "sub_sp_total": info.sub_sp_total,
        "stack_frame": info.stack_frame,
        "source": info.source,
        "prologue_ops": info.prologue_ops,
        "note": "model value, not a runtime peak; alloca/register spilling/stack protector change real usage",
    }


def tool_stackdepth(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    limit = _max_chars(args)
    entry = _string(args, "entry")
    config = core.StackDepthConfig(
        indirect_penalty=_int(args, "indirect_penalty", 80),
        context_bytes=_int(args, "context_bytes", 0),
        safety_factor=_number(args, "safety_factor", 1.5),
    )
    root = analyzer.analyze_stack_depth(entry, config=config)
    if root is None:
        raise ToolError("FUNCTION_NOT_FOUND", f"function not found: {entry}")

    def _has_cycle(node: Any) -> bool:
        return node.is_cycle or any(_has_cycle(child) for child in node.children)

    static_depth = root.cumulative_depth - root.total_indirect_count * config.indirect_penalty
    indirect_total = root.total_indirect_count * config.indirect_penalty
    base_total = root.cumulative_depth + config.context_bytes
    return {
        "axf": str(path),
        "entry": entry,
        "config": {
            "indirect_penalty": config.indirect_penalty,
            "context_bytes": config.context_bytes,
            "safety_factor": config.safety_factor,
        },
        "summary": {
            "own_frame": root.own_frame,
            "static_depth": static_depth,
            "indirect_total": indirect_total,
            "indirect_levels": root.total_indirect_count,
            "context_bytes": config.context_bytes,
            "base_total": base_total,
            "required_bytes": __import__("math").ceil(base_total * config.safety_factor),
            "has_cycle": _has_cycle(root),
        },
        "tree": _node_dict(root),
        "text": _text(analyzer.format_stack_depth_tree(root, config=config), limit),
        "warning": "model value; recursion/re-entry means the true worst case is unknown; a fitting model is not a safety proof",
    }


def tool_audit_tasks(args: dict[str, Any]) -> dict[str, Any]:
    analyzer, path = _open_analyzer(_string(args, "axf"))
    limit = _max_chars(args)
    manifest = args.get("manifest")
    if isinstance(manifest, str):
        manifest_path = Path(manifest).expanduser().resolve()
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as error:
            raise ToolError("BAD_MANIFEST", f"cannot read manifest: {error}") from error
    if not isinstance(manifest, dict):
        raise ToolError("BAD_MANIFEST", "`manifest` must be an object or the path to a JSON file")
    project_root = Path(args.get("project_root") or ".").expanduser().resolve()
    try:
        report = analyzer.audit_tasks(manifest, project_root)
    except (ValueError, KeyError, TypeError) as error:
        raise ToolError("BAD_MANIFEST", f"manifest rejected: {error}") from error
    return {
        "axf": str(path),
        "manifest_schema_version": manifest.get("schema_version"),
        "report": report,
        "text": _text(analyzer.format_task_audit(report), limit),
        "warning": "the entry list and allocation budget come from the manifest; the tool does not discover entries or infer units",
    }


HANDLERS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "axf_file_info": tool_file_info,
    "axf_build_info": tool_build_info,
    "axf_symbols_top": tool_symbols_top,
    "axf_unused": tool_unused,
    "axf_segments": tool_segments,
    "axf_symbol_addr": tool_symbol_addr,
    "axf_checksum": tool_checksum,
    "axf_addr2line": tool_addr2line,
    "axf_disasm": tool_disasm,
    "axf_struct": tool_struct,
    "axf_callgraph": tool_callgraph,
    "axf_stackframe": tool_stackframe,
    "axf_stackdepth": tool_stackdepth,
    "axf_audit_tasks": tool_audit_tasks,
}

# --------------------------------------------------------------------------- #
# Tool registry
# --------------------------------------------------------------------------- #

_AXF = {
    "type": "string",
    "description": "Absolute or relative path to the firmware .axf/ELF file. Required on every tool.",
}
_MAX_CHARS = {
    "type": "integer",
    "description": "Truncate text output to this many characters (default 20000, max 200000).",
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "axf_file_info",
        "description": "Identify the image: absolute path, byte size and SHA256. Quote the hash with any finding.",
        "inputSchema": {"type": "object", "properties": {"axf": _AXF}, "required": ["axf"], "additionalProperties": False},
    },
    {
        "name": "axf_build_info",
        "description": "Build/toolchain facts: architecture, CPU, FPU/float ABI, alignment, compiler, optimization level.",
        "inputSchema": {"type": "object", "properties": {"axf": _AXF}, "required": ["axf"], "additionalProperties": False},
    },
    {
        "name": "axf_symbols_top",
        "description": "Function/data objects ranked by size. Use region=ram for real RAM usage (excludes .rodata constants).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "axf": _AXF,
                "kind": {"type": "string", "enum": ["all", "func", "data"], "description": "Default: all."},
                "region": {"type": "string", "enum": ["all", "ram", "flash"], "description": "Default: all."},
                "limit": {"type": "integer", "description": "Number of rows (default 20)."},
            },
            "required": ["axf"],
            "additionalProperties": False,
        },
    },
    {
        "name": "axf_unused",
        "description": "Candidates for unreferenced static objects (best effort). Not a safe-to-delete list.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "axf": _AXF,
                "min_size": {"type": "integer", "description": "Only report objects at least this many bytes."},
                "include_funcs": {"type": "boolean", "description": "Also list functions (high false-positive rate)."},
                "limit": {"type": "integer", "description": "Number of rows (default 20)."},
            },
            "required": ["axf"],
            "additionalProperties": False,
        },
    },
    {
        "name": "axf_segments",
        "description": "Program headers / segment map: type, vaddr, paddr, file/memory size and flags.",
        "inputSchema": {"type": "object", "properties": {"axf": _AXF}, "required": ["axf"], "additionalProperties": False},
    },
    {
        "name": "axf_symbol_addr",
        "description": "Absolute address, size, type and section of one symbol.",
        "inputSchema": {
            "type": "object",
            "properties": {"axf": _AXF, "name": {"type": "string", "description": "Symbol name."}},
            "required": ["axf", "name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "axf_checksum",
        "description": "SHA256 of the requested sections (default .text,.rodata,.data) for firmware version comparison.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "axf": _AXF,
                "sections": {"type": "array", "items": {"type": "string"},
                             "description": "Section names, e.g. [\".text\", \".rodata\"]."},
            },
            "required": ["axf"],
            "additionalProperties": False,
        },
    },
    {
        "name": "axf_addr2line",
        "description": "Map a crash/PC address (hex, e.g. 0x08001234) to source file:line, expanding the inline chain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "axf": _AXF,
                "address": {"type": "string", "description": "Hexadecimal address such as 0x08001234."},
            },
            "required": ["axf", "address"],
            "additionalProperties": False,
        },
    },
    {
        "name": "axf_disasm",
        "description": "Disassemble one function; mixed=true interleaves source lines. Hex dump when capstone is absent.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "axf": _AXF,
                "function": {"type": "string", "description": "Function/symbol name."},
                "mixed": {"type": "boolean", "description": "Interleave source lines (needs DWARF)."},
                "max_chars": _MAX_CHARS,
            },
            "required": ["axf", "function"],
            "additionalProperties": False,
        },
    },
    {
        "name": "axf_struct",
        "description": "Real DWARF memory layout of a struct/union: member offsets, types, bitfields, total size.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "axf": _AXF,
                "name": {"type": "string", "description": "Struct/union name (anonymous typedefs supported)."},
                "expand": {"type": "boolean", "description": "Recursively expand nested structs."},
            },
            "required": ["axf", "name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "axf_callgraph",
        "description": "Static call tree from ELF relocations (direct calls only; no pointers, tail calls, inlined or dead code).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "axf": _AXF,
                "function": {"type": "string", "description": "Function/symbol name."},
                "depth": {"type": "integer", "description": "Recursion depth (default 2)."},
                "max_chars": _MAX_CHARS,
            },
            "required": ["axf", "function"],
            "additionalProperties": False,
        },
    },
    {
        "name": "axf_stackframe",
        "description": "Modelled stack frame of one function (DWARF CFI first, Thumb prologue-scan fallback) with its evidence source.",
        "inputSchema": {
            "type": "object",
            "properties": {"axf": _AXF, "function": {"type": "string", "description": "Function/symbol name."}},
            "required": ["axf", "function"],
            "additionalProperties": False,
        },
    },
    {
        "name": "axf_stackdepth",
        "description": "Modelled stack depth along the deepest call chain from ANY entry symbol (main, ISR, task function, test). No RTOS assumptions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "axf": _AXF,
                "entry": {"type": "string", "description": "Entry function/symbol name."},
                "context_bytes": {"type": "integer", "description": "Extra context budget in bytes (default 0 = not included)."},
                "indirect_penalty": {"type": "integer", "description": "Bytes added per indirect-call level (default 80, not a bound)."},
                "safety_factor": {"type": "number", "description": "Model multiplier (default 1.5)."},
                "max_chars": _MAX_CHARS,
            },
            "required": ["axf", "entry"],
            "additionalProperties": False,
        },
    },
    {
        "name": "axf_audit_tasks",
        "description": "Optional budget audit: compare the model against a project-owned manifest (schema_version=2) of entries and allocations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "axf": _AXF,
                "manifest": {"description": "Manifest object, or a path to the JSON manifest file."},
                "project_root": {"type": "string", "description": "Root used to resolve allocation source paths (default: cwd)."},
                "max_chars": _MAX_CHARS,
            },
            "required": ["axf", "manifest"],
            "additionalProperties": False,
        },
    },
]


# --------------------------------------------------------------------------- #
# JSON-RPC transport
# --------------------------------------------------------------------------- #


def _tool_result(payload: dict[str, Any], *, is_error: bool) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
        "isError": is_error,
    }


def _call_tool(params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments")
    if not isinstance(name, str) or name not in HANDLERS:
        return _tool_result({"ok": False, "error": {"code": "UNKNOWN_TOOL", "message": f"unknown tool: {name!r}"}}, is_error=True)
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return _tool_result({"ok": False, "error": {"code": "BAD_ARGUMENT", "message": "`arguments` must be an object"}}, is_error=True)
    try:
        data = HANDLERS[name](arguments)
    except ToolError as error:
        payload: dict[str, Any] = {"ok": False, "error": {"code": error.code, "message": error.message}}
        if error.details is not None:
            payload["error"]["details"] = error.details
        return _tool_result(payload, is_error=True)
    except Exception as error:  # noqa: BLE001 - a tool failure must not kill the server
        traceback.print_exc(file=sys.stderr)
        return _tool_result({"ok": False, "error": {"code": "INTERNAL", "message": str(error)}}, is_error=True)
    return _tool_result({"ok": True, "data": data}, is_error=False)


def _initialize(_params: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        "instructions": (
            "Read-only firmware image analysis. Always pass `axf` explicitly; never guess which firmware to analyze. "
            "Prefer images built with -O0/-Og and -g: inlining at -O2/-O3 hides functions from addr2line/callgraph/stack analysis. "
            "axf_callgraph covers static direct calls only; axf_unused is a candidate list, not a deletion proof. "
            "A fitting stack model is not a safety proof; report the image hash with every finding."
        ),
    }


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    is_notification = "id" not in message or request_id is None
    params = message.get("params")
    if not isinstance(params, dict):
        params = {}

    if method is None:
        return None if is_notification else {"jsonrpc": "2.0", "id": request_id,
                                             "error": {"code": -32600, "message": "invalid request: missing method"}}
    if method in ("notifications/initialized", "notifications/cancelled", "notifications/roots/list_changed"):
        return None
    try:
        if method == "initialize":
            result: Any = _initialize(params)
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            result = _call_tool(params)
        elif method == "resources/list":
            result = {"resources": []}
        elif method == "prompts/list":
            result = {"prompts": []}
        else:
            return None if is_notification else {"jsonrpc": "2.0", "id": request_id,
                                                 "error": {"code": -32601, "message": f"method not found: {method}"}}
    except Exception as error:  # noqa: BLE001 - protocol-level failure
        traceback.print_exc(file=sys.stderr)
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32603, "message": str(error)}}
    if is_notification:
        return None
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _emit(stdout: Any, text: str) -> None:
    """Write one protocol frame as UTF-8 regardless of the console code page."""
    data = (text + "\n").encode("utf-8")
    buffer = getattr(stdout, "buffer", None)
    if buffer is not None:
        buffer.write(data)
        buffer.flush()
    else:
        stdout.write(text + "\n")
        stdout.flush()


def serve(stdin: Any = None, stdout: Any = None) -> int:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout
    for raw in stdin:
        line = raw.decode("utf-8", errors="replace").strip() if isinstance(raw, (bytes, bytearray)) else str(raw).strip()
        if line == "":
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            _emit(stdout, json.dumps({"jsonrpc": "2.0", "id": None,
                                      "error": {"code": -32700, "message": f"parse error: {error}"}}))
            continue
        if not isinstance(message, dict):
            _emit(stdout, json.dumps({"jsonrpc": "2.0", "id": None,
                                      "error": {"code": -32600, "message": "invalid request: expected an object"}}))
            continue
        response = handle(message)
        if response is not None:
            _emit(stdout, json.dumps(response, ensure_ascii=False))
    return 0


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass
    try:
        return serve()
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
