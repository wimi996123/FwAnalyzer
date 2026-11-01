#!/usr/bin/env python3
"""
AxFInspector - 基于 pyelftools 的 ELF/DWARF 符号级分析器

用法:
    python axf_inspector.py --axf <固件文件> <子命令> [参数]

子命令:
    --addr2line <hex_address>       地址转源码位置（含内联展开）
    --callstack <address>           --addr2line 的别名
    --disasm <function_name>        函数反汇编 [--mixed]
    --stackframe <func_name>        函数栈帧分析（Thumb 前言解码）
    --top [--type func|data] [--region all|ram|flash] [--limit N]  最大符号排行榜
    --unused [--min-size N] [--include-funcs]  死符号候选（静态数据对象）
    --struct <struct_name>          结构体布局可视化 [--expand]
    --callgraph <function_name>     静态调用图 [--depth N]
    --segments                      内存映射视图
    --build-info                    编译环境与 ABI 属性
    --symbol-addr <symbol_name>     符号地址查询
    --checksum [--section ...]      固件校验与比对
"""

import sys
import os
import hashlib
import argparse
import struct
import math
import json
import re
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field

# ============================================================
# 依赖检测
# ============================================================

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.segments import Segment
    from elftools.elf.sections import Section, SymbolTableSection
    from elftools.elf.relocation import RelocationSection
    from elftools.dwarf.dwarfinfo import DWARFInfo
    from elftools.dwarf.descriptions import describe_DWARF_expr, set_global_machine_arch
    from elftools.dwarf.enums import ENUM_DW_TAG, ENUM_DW_AT
    _pyelftools_available = True
except ImportError:
    _pyelftools_available = False

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
    _capstone_available = True
except ImportError:
    _capstone_available = False


# ============================================================
# 数据类
# ============================================================

@dataclass
class InlineFrame:
    """内联调用栈中的一帧"""
    file: str
    line: int
    column: int = 0
    function: str = ""

    def __str__(self):
        base = f"{self.file}:{self.line}"
        if self.column:
            base += f":{self.column}"
        if self.function:
            base += f" ({self.function})"
        return base


@dataclass
class Member:
    """结构体/联合体成员布局"""
    name: str
    type_name: str
    offset: int           # 字节偏移
    size: int = 0         # 字节大小
    bit_offset: int = -1  # 位域起始 bit（-1 表示非位域）
    bit_size: int = 0     # 位域宽度（0 表示非位域）
    children: list = field(default_factory=list)  # 嵌套子成员（用于 recursive expand）

    def __str__(self):
        if self.bit_size > 0:
            return f"+{self.offset:#06x}  {self.type_name:30s} {self.name:<20s} (bit {self.bit_offset}, width {self.bit_size})"
        return f"+{self.offset:#06x}  {self.type_name:30s} {self.name}"


@dataclass
class CallGraphNode:
    """调用图节点"""
    name: str
    address: int = 0
    callers: list = field(default_factory=list)     # list of CallGraphNode
    callees: list = field(default_factory=list)     # list of CallGraphNode


@dataclass
class SegInfo:
    """段信息"""
    seg_type: str
    vaddr: int
    paddr: int
    file_size: int
    mem_size: int
    flags: str


@dataclass
class SymbolInfo:
    """符号信息"""
    name: str
    address: int
    size: int
    st_type: str
    section: str
    region: str = ''      # RAM / FLASH / OTHER（按节属性判定）


@dataclass
class StackFrameInfo:
    """函数栈帧分析结果"""
    name: str                       # 函数名
    address: int                    # 虚拟地址（含 Thumb 位）
    code_size: int                  # 函数代码大小
    is_thumb: bool                  # 是否 Thumb 模式
    push_bytes: int = 0             # PUSH 保存的寄存器字节数
    push_regs: list = field(default_factory=list)   # PUSH 的寄存器名列表
    sub_sp_total: int = 0           # SUB SP 累计分配的局部变量空间
    stack_frame: int = 0            # 总栈帧 = push_bytes + sub_sp_total
    prologue_ops: list = field(default_factory=list)  # 前言指令的人类可读描述
    raw_bytes_hex: str = ""         # 函数前 N 字节 hex
    source: str = "prologue"        # 栈帧数据来源: dwarf_cfi / prologue

    def __str__(self):
        mode = "Thumb" if self.is_thumb else "ARM"
        lines = [
            f"--- {self.name} @ 0x{self.address:08X} ({mode}, code={self.code_size}B) ---",
            f"  Raw: {self.raw_bytes_hex}",
        ]
        for op in self.prologue_ops:
            lines.append(f"  {op}")
        lines.append(f"  => PUSH: {len(self.push_regs)} regs ({self.push_bytes}B) + SUB SP: {self.sub_sp_total}B = {self.stack_frame}B")
        return '\n'.join(lines)


@dataclass
class StackDepthNode:
    """调用链栈深度分析节点"""
    func_name: str                  # 函数名
    address: int                    # 函数地址
    own_frame: int                  # 自身栈帧大小（字节）
    cumulative_depth: int = 0       # 累计最大栈深度（自身 + 最深子调用链）
    indirect_count: int = 0         # 本函数内间接调用（BLX Rn）条数
    total_indirect_count: int = 0   # 最深路径中含间接调用的函数层数
    is_leaf: bool = False           # 是否为叶子函数（无子调用）
    is_cycle: bool = False          # 是否因当前路径形成环而停止展开
    frame_source: str = "unknown"  # 自身栈帧数据来源
    children: list = field(default_factory=list)  # 子节点列表


@dataclass
class StackDepthConfig:
    """--stackdepth 估算配置"""
    indirect_penalty: int = 80      # 每个含间接调用的路径层级的启发式预算
    context_bytes: int = 0          # 调度/异常上下文预算；由目标移植层证据决定
    safety_factor: float = 1.5      # 最终安全系数


# ============================================================
# ELFAnalyzer 核心类
# ============================================================

def calculate_stack_budget(modeled_bytes: int, context_bytes: int,
                           allocated_units: int, unit_bytes: int,
                           minimum_units: int = 0, granularity_units: int = 1,
                           safety_factor: float = 1.5) -> dict:
    """Calculate a stack budget using target-defined allocation units."""
    for name, value in (('modeled_bytes', modeled_bytes),
                        ('context_bytes', context_bytes),
                        ('allocated_units', allocated_units),
                        ('unit_bytes', unit_bytes),
                        ('minimum_units', minimum_units),
                        ('granularity_units', granularity_units)):
        if type(value) is not int or value < 0:
            raise ValueError(f'{name} must be a nonnegative integer')
    if allocated_units == 0 or unit_bytes == 0 or granularity_units == 0:
        raise ValueError('allocated_units, unit_bytes and granularity_units must be positive')
    if isinstance(safety_factor, bool) or not math.isfinite(safety_factor) or safety_factor < 1:
        raise ValueError('safety_factor must be finite and >= 1')
    base_bytes = modeled_bytes + context_bytes
    required_bytes = math.ceil(base_bytes * safety_factor)
    required_units = math.ceil(required_bytes / unit_bytes)
    recommended_units = max(
        minimum_units,
        math.ceil(required_units / granularity_units) * granularity_units,
    )
    allocated_bytes = allocated_units * unit_bytes
    return {
        'modeled_bytes': modeled_bytes,
        'context_bytes': context_bytes,
        'base_bytes': base_bytes,
        'required_bytes': required_bytes,
        'required_units': required_units,
        'recommended_units': recommended_units,
        'recommended_bytes': recommended_units * unit_bytes,
        'allocated_units': allocated_units,
        'allocated_bytes': allocated_bytes,
        'unit_bytes': unit_bytes,
        'minimum_units': minimum_units,
        'granularity_units': granularity_units,
        'base_ratio': base_bytes / allocated_bytes,
        'required_ratio': required_bytes / allocated_bytes,
        'recommendation_ratio': recommended_units / allocated_units,
        'model_exceeds_allocation': required_bytes > allocated_bytes,
    }


class ELFAnalyzer:
    """核心分析器，封装所有 ELF 解析逻辑"""

    # ARM 调用类重定位类型
    ARM_CALL_RELOC_TYPES = {
        'R_ARM_CALL', 'R_ARM_JUMP24', 'R_ARM_THM_CALL',
        'R_ARM_THM_JUMP24', 'R_ARM_THM_JUMP19', 'R_ARM_PC24',
        'R_ARM_THM_CALL', 'R_ARM_THM_JUMP24',
    }

    def __init__(self, path: str):
        if not _pyelftools_available:
            sys.exit(
                "错误: 缺少 pyelftools 库。请安装:\n"
                "  pip install pyelftools>=0.29"
            )

        if not os.path.isfile(path):
            sys.exit(f"错误: 文件不存在: {path}")

        self.path = path
        self._elffile: ELFFile = None
        self._symtab: SymbolTableSection = None
        self._dwarf_info: DWARFInfo = None
        self._section_names: dict[str, Section] = {}
        self._has_debug_info = False

        self._load()

    def _load(self):
        """加载并缓存 ELF 文件关键数据结构"""
        self._fileobj = open(self.path, 'rb')
        self._elffile = ELFFile(self._fileobj)
        self._file_data = self._fileobj.read()

        # 缓存节区
        for sec in self._elffile.iter_sections():
            name = sec.name
            self._section_names[name] = sec

        # 获取符号表
        symtab = self._elffile.get_section_by_name('.symtab')
        if symtab and isinstance(symtab, SymbolTableSection):
            self._symtab = symtab

        # DWARF 信息
        if self._elffile.has_dwarf_info():
            self._dwarf_info = self._elffile.get_dwarf_info()
            self._has_debug_info = True

    # ---- 基础查询 ----

    def get_section(self, name: str):
        return self._section_names.get(name)

    def get_symbol(self, name: str):
        if not self._symtab:
            return None
        syms = self._symtab.get_symbol_by_name(name)
        return syms[0] if syms else None

    def get_all_symbols(self):
        """返回所有非零大小符号列表"""
        if not self._symtab:
            return []
        symbols = []
        for sym in self._symtab.iter_symbols():
            if sym['st_size'] > 0 and sym['st_info']['type'] in ('STT_FUNC', 'STT_OBJECT'):
                symbols.append(sym)
        return symbols

    # ============================================================
    # --segments (阶段1)
    # ============================================================

    def get_segments(self) -> list[SegInfo]:
        """获取程序头/段信息"""
        segments = []
        for seg in self._elffile.iter_segments():
            flags = ''
            if seg.header.p_flags & 4:
                flags += 'R'
            if seg.header.p_flags & 2:
                flags += 'W'
            if seg.header.p_flags & 1:
                flags += 'E'

            seg_type = seg.header.p_type
            type_names = {
                'PT_LOAD': 'LOAD',
                'PT_DYNAMIC': 'DYNAMIC',
                'PT_INTERP': 'INTERP',
                'PT_NOTE': 'NOTE',
                'PT_PHDR': 'PHDR',
                'PT_GNU_STACK': 'GNU_STACK',
                'PT_GNU_RELRO': 'GNU_RELRO',
                'PT_GNU_EH_FRAME': 'GNU_EH_FRAME',
                'PT_ARM_EXIDX': 'ARM_EXIDX',
            }
            seg_type_display = type_names.get(seg_type, seg_type)

            segments.append(SegInfo(
                seg_type=seg_type_display,
                vaddr=seg.header.p_vaddr,
                paddr=seg.header.p_paddr,
                file_size=seg.header.p_filesz,
                mem_size=seg.header.p_memsz,
                flags=flags,
            ))
        return segments

    # ============================================================
    # --top + --symbol-addr (阶段2)
    # ============================================================

    def _section_region(self, sym) -> str:
        """按节属性判定符号所在区域。

        规则（与架构无关）：SHF_ALLOC 且 SHF_WRITE → RAM（.data/.bss）；
        SHF_ALLOC 但不可写 → FLASH（.text/.rodata）；其余 → OTHER（调试等）。
        """
        if sym['st_shndx'] == 'SHN_UNDEF':
            return 'OTHER'
        try:
            sec = self._elffile.get_section(sym['st_shndx'])
        except Exception:
            return 'OTHER'
        if sec is None:
            return 'OTHER'
        flags = sec['sh_flags']
        if not (flags & 0x2):          # SHF_ALLOC
            return 'OTHER'
        return 'RAM' if (flags & 0x1) else 'FLASH'   # SHF_WRITE

    def get_symbols_sorted_by_size(self, st_type: str = None,
                                   region: str = None) -> list[SymbolInfo]:
        """按大小降序排列符号。

        region: 'ram' / 'flash' / None(全部)。用户真正关心"内存占用"时应传 ram，
        否则会把 .rodata 里的常量表也算进来（大但不在 RAM）。
        """
        symbols = self.get_all_symbols()
        if st_type == 'func':
            symbols = [s for s in symbols if s['st_info']['type'] == 'STT_FUNC']
        elif st_type == 'data':
            symbols = [s for s in symbols if s['st_info']['type'] == 'STT_OBJECT']

        want_region = (region or '').upper()
        if want_region in ('RAM', 'FLASH'):
            symbols = [s for s in symbols if self._section_region(s) == want_region]

        symbols.sort(key=lambda s: s['st_size'], reverse=True)

        result = []
        for sym in symbols:
            st_type_name = sym['st_info']['type']
            type_display = {
                'STT_FUNC': 'FUNC',
                'STT_OBJECT': 'OBJECT',
            }.get(st_type_name, st_type_name)

            section_name = ''
            if sym['st_shndx'] != 'SHN_UNDEF':
                try:
                    sec = self._elffile.get_section(sym['st_shndx'])
                    if sec:
                        section_name = sec.name
                except Exception:
                    section_name = str(sym['st_shndx'])

            result.append(SymbolInfo(
                name=sym.name,
                address=sym['st_value'],
                size=sym['st_size'],
                st_type=type_display,
                section=section_name,
                region=self._section_region(sym),
            ))
        return result

    def get_symbol_addr(self, symbol_name: str) -> SymbolInfo | None:
        """查询符号地址"""
        sym = self.get_symbol(symbol_name)
        if not sym:
            return None

        section_name = ''
        if sym['st_shndx'] != 'SHN_UNDEF':
            try:
                sec = self._elffile.get_section(sym['st_shndx'])
                if sec:
                    section_name = sec.name
            except Exception:
                section_name = str(sym['st_shndx'])

        st_type_name = sym['st_info']['type']
        type_display = {
            'STT_FUNC': 'FUNC',
            'STT_OBJECT': 'OBJECT',
            'STT_NOTYPE': 'NOTYPE',
        }.get(st_type_name, st_type_name)

        return SymbolInfo(
            name=sym.name,
            address=sym['st_value'],
            size=sym['st_size'],
            st_type=type_display,
            section=section_name,
        )

    # ============================================================
    # --stackframe (解码 Thumb 函数前言，分析栈帧)
    # ============================================================

    # 寄存器名称映射（Thumb PUSH 编码中的寄存器位）
    _REG_NAMES_THUMB16 = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7']
    _REG_NAMES_THUMB32 = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
                          'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc']

    def _build_cfi_stack_map(self):
        """从 DWARF CFI 构建函数地址到最大 CFA 偏移的映射。"""
        if hasattr(self, '_cfi_stack_map'):
            return

        self._cfi_stack_map = {}
        if not self._dwarf_info:
            return

        try:
            entries = self._dwarf_info.CFI_entries()
        except Exception:
            return

        for entry in entries:
            if not hasattr(entry, 'get_decoded'):
                continue
            try:
                start = entry['initial_location'] & ~1
                rows = entry.get_decoded().table
                if any(row.get('cfa') is None or row['cfa'].expr is not None
                       or row['cfa'].reg != 13 for row in rows):
                    continue
                offsets = [
                    row['cfa'].offset for row in rows
                    if row.get('cfa') is not None
                    and row['cfa'].expr is None
                    and isinstance(row['cfa'].offset, int)
                ]
                if offsets:
                    self._cfi_stack_map[start] = max(offsets)
            except Exception:
                continue

    def analyze_stackframe(self, func_name: str, max_prologue: int = 256) -> StackFrameInfo | None:
        """
        分析函数的栈帧大小（通过解码 Thumb 前言）。

        解析 PUSH 和 SUB SP 指令，累计计算函数在栈上分配的
        总空间（PUSH 寄存器 + 局部变量）。

        @param func_name:  函数符号名
        @param max_prologue: 分析前言的字节数上限 (默认 30)
        @return: StackFrameInfo，若符号未找到则返回 None
        """
        sym = self.get_symbol(func_name)
        if not sym:
            return None

        if sym['st_info']['type'] != 'STT_FUNC':
            return None

        start_addr = sym['st_value']
        size = sym['st_size']
        is_thumb = (start_addr & 1) == 1
        real_addr = start_addr & ~1

        # 编译器生成的 CFI 描述所有前言状态，优先级高于机器码启发式扫描。
        self._build_cfi_stack_map()
        cfi_frame = self._cfi_stack_map.get(real_addr)
        if cfi_frame is not None:
            return StackFrameInfo(
                name=func_name,
                address=start_addr,
                code_size=size,
                is_thumb=is_thumb,
                stack_frame=cfi_frame,
                prologue_ops=[f"DWARF CFA 最大偏移: {cfi_frame}B"],
                source="dwarf_cfi",
            )

        read_size = min(size if size > 0 else 40, max_prologue)

        # 从 segment 中读取机器码
        data = self._read_bytes(real_addr, read_size)
        if not data:
            return None

        raw_hex = data[:read_size].hex(' ')

        # 解码前言
        push_regs = []
        push_bytes = 0
        sub_sp_total = 0
        ops = []
        offset = 0

        while offset < min(len(data), max_prologue):
            if offset + 2 > len(data):
                break
            hw = struct.unpack_from('<H', data, offset)[0]

            # 检测 32 位 Thumb-2 指令（高 5 位 0b11101 / 0b11110 / 0b11111）
            is_32bit = (hw >> 11) >= 0x1D

            if is_32bit and offset + 4 <= len(data):
                hw2 = struct.unpack_from('<H', data, offset + 2)[0]

                # SUB.W SP, SP, #imm12 (T2: 0xF1AD 0x0Dxx)
                if (hw & 0xFBFF) == 0xF1AD and (hw2 & 0xFF00) == 0x0D00:
                    imm12 = (hw2 & 0xFF) | ((hw & 0x0400) << 1)
                    sub_sp_total += imm12
                    ops.append(f"SUB.W SP, SP, #{imm12}")
                # SUBW SP, SP, #imm12 (T4: 0xF2AD 0x0Dxx)
                elif (hw & 0xFBFF) == 0xF2AD and (hw2 & 0xFF00) == 0x0D00:
                    imm12 = hw2 & 0xFFF
                    sub_sp_total += imm12
                    ops.append(f"SUBW SP, SP, #{imm12}")
                # PUSH.W {regs} (0xE92D xxxx)
                elif hw == 0xE92D:
                    bitmap = hw2
                    push_regs = [self._REG_NAMES_THUMB32[i] for i in range(16) if bitmap & (1 << i)]
                    push_bytes = len(push_regs) * 4
                    ops.append(f"PUSH.W {{{', '.join(push_regs)}}} ({len(push_regs)} regs)")
                # POP.W / ADDW (epilogue) → 停止解析
                elif hw == 0xE8BD:
                    break
                offset += 4
            else:
                # 16 位 Thumb 指令
                # PUSH {regs}: 1011 010x xxxx xxxx (0xB400)
                if (hw & 0xFE00) == 0xB400:
                    bitmap = hw & 0xFF
                    push_regs = []
                    for i in range(8):
                        if bitmap & (1 << i):
                            push_regs.append(self._REG_NAMES_THUMB16[i])
                    if hw & 0x0100:
                        push_regs.append('lr')
                    push_bytes = len(push_regs) * 4
                    ops.append(f"PUSH {{{', '.join(push_regs)}}} ({len(push_regs)} regs)")
                # SUB SP, #imm7*4: 1011 0000 1xxx xxxx (0xB080)
                elif (hw & 0xFF80) == 0xB080:
                    imm7 = hw & 0x7F
                    sub_sp_total += imm7 * 4
                    ops.append(f"SUB SP, #{imm7 * 4}")
                # ADD SP / POP (epilogue) → 停止解析
                elif (hw & 0xFF80) == 0xB000 or (hw & 0xFE00) == 0xBC00:
                    break
                offset += 2

        stack_frame = push_bytes + sub_sp_total
        return StackFrameInfo(
            name=func_name,
            address=start_addr,
            code_size=size,
            is_thumb=is_thumb,
            push_bytes=push_bytes,
            push_regs=push_regs,
            sub_sp_total=sub_sp_total,
            stack_frame=stack_frame,
            prologue_ops=ops,
            raw_bytes_hex=raw_hex,
            source="prologue",
        )

    def _read_bytes(self, vaddr: int, size: int) -> bytes | None:
        """从 ELF 中读取指定虚拟地址的原始字节。

        优先走加载段（PT_LOAD）；部分 Keil/AXF 产物没有可用的段表，
        此时回退到按节（sh_addr/sh_size）查找 —— 否则 --disasm / --stackdepth /
        --unused 的指令级分析会全部静默失效。
        """
        for seg in self._elffile.iter_segments():
            if seg.header.p_vaddr <= vaddr < seg.header.p_vaddr + seg.header.p_filesz:
                offset = vaddr - seg.header.p_vaddr
                data = seg.data()
                return data[offset:offset + size]

        for sec in self._elffile.iter_sections():
            try:
                addr = sec['sh_addr']
                sz = sec['sh_size']
                stype = sec['sh_type']
            except Exception:
                continue
            if stype == 'SHT_NOBITS' or sz == 0:
                continue
            if addr <= vaddr < addr + sz:
                try:
                    data = sec.data()
                except Exception:
                    continue
                off = vaddr - addr
                return data[off:off + size]
        return None

    # ============================================================
    # --stackdepth (递归调用链栈深度分析)
    # ============================================================

    # Thumb BL 指令编码常量
    # BL:  first  halfword bits[15:11]=11110, bit[10]=S=0
    # BLX: first  halfword bits[15:11]=11111, bit[10]=S=1
    #       second halfword: bit[15]=1, bit[14]=1, bit[12]=1

    def _build_addr_to_name_map(self):
        """惰性构建 地址→函数名 映射（缓存）"""
        if hasattr(self, '_addr_to_name'):
            return
        self._addr_to_name = {}
        if self._symtab:
            for sym in self._symtab.iter_symbols():
                if sym['st_info']['type'] == 'STT_FUNC':
                    addr = sym['st_value'] & ~1
                    self._addr_to_name[addr] = sym.name

    def _find_func_name_by_addr(self, addr: int) -> str | None:
        """通过地址查找函数名"""
        self._build_addr_to_name_map()
        return self._addr_to_name.get(addr & ~1)

    def _decode_bl_instructions(self, data: bytes, base_addr: int) -> list[tuple[int, str]]:
        """
        解码函数机器码中的 BL/BLX 指令，返回目标地址列表。

        @param data:      函数机器码字节
        @param base_addr: 函数起始虚拟地址（已清除 Thumb 位）
        @return: [(target_addr, func_name|None), ...]
        """
        targets = []
        offset = 0
        while offset + 1 < len(data):
            hw = struct.unpack_from('<H', data, offset)[0]

            # 检测 32 位 Thumb-2 指令（bits[15:11] >= 0x1D）
            is_32bit = (hw >> 11) >= 0x1D

            if is_32bit and offset + 3 < len(data):
                hw2 = struct.unpack_from('<H', data, offset + 2)[0]

                # BL / BLX label 指令: first halfword bits[15:11]=11110(BL) or 11111(BLX)
                hi5 = (hw >> 11) & 0x1F
                if hi5 == 0x1E or hi5 == 0x1F:
                    # second halfword: bit[15]=1, bit[14]=1, bit[12]=1
                    if (hw2 & 0xD000) == 0xD000:
                        # 解码目标地址
                        S = (hw >> 10) & 1
                        imm10 = hw & 0x3FF
                        J1 = (hw2 >> 13) & 1
                        J2 = (hw2 >> 11) & 1
                        imm11 = hw2 & 0x7FF
                        I1 = 1 - (J1 ^ S)
                        I2 = 1 - (J2 ^ S)
                        offset_target = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
                        # 符号扩展 25 位
                        if offset_target & (1 << 24):
                            offset_target -= (1 << 25)
                        target_addr = (base_addr + offset + 4 + offset_target) & 0xFFFFFFFF
                        func_name = self._find_func_name_by_addr(target_addr)
                        targets.append((target_addr, func_name))

                offset += 4
            else:
                offset += 2

        return targets

    def _detect_fpu(self) -> tuple[bool, str]:
        """
        通过 ELF build attributes 检测 FPU 配置。

        @return: (has_fpu, arch_name)  e.g. (True, "Cortex-M4")
        """
        has_fpu = False
        arch_name = "Unknown"

        # ELF ARM ABI 标志（GNU/LLVM ELF 常见；Keil AXF 可能不设置）。
        elf_flags = self._elffile.header.get('e_flags', 0)
        if isinstance(elf_flags, int) and (elf_flags & 0x400):
            return True, "ARM hard-float ABI"

        build_attrs = self._elffile.get_section_by_name('.ARM.attributes')
        if build_attrs:
            data = build_attrs.data()
            try:
                # ARM build attributes section:  vendor string + subsections
                pos = 0
                # Skip vendor tag (format: 'A' + version byte)
                if len(data) > 4 and data[0:1] == b'A':
                    vendor_len = data[3]
                    pos = 4 + vendor_len

                # Parse subsections
                while pos + 3 < len(data):
                    tag = data[pos]
                    sub_len = struct.unpack_from('<I', data, pos)[0]
                    if sub_len == 0:
                        break
                    # tag=1: File Attributes
                    if tag == 1:
                        payload = data[pos + 4:pos + sub_len]
                        i = 0
                        while i < len(payload):
                            if i >= len(payload):
                                break
                            attr_tag = payload[i]
                            if attr_tag == 0:
                                break
                            i += 1
                            if i >= len(payload):
                                break
                            if attr_tag == 4:  # Tag_CPU_arch
                                arch_val = payload[i]
                                i += 1
                                arch_map = {5: 'ARMv4', 6: 'ARMv5', 7: 'ARMv6',
                                            8: 'ARMv7', 9: 'ARMv8'}
                                arch_ver = arch_map.get(arch_val, f'ARMv{arch_val}')
                            elif attr_tag == 5:  # Tag_CPU_arch_profile
                                profile_val = payload[i]
                                i += 1
                                profile_map = {0: '', ord('A'): 'A', ord('R'): 'R',
                                               ord('M'): 'M'}
                                profile = profile_map.get(profile_val, '')
                                arch_name = f"Cortex-{arch_ver}-{profile}" if profile else arch_ver
                            elif attr_tag == 6:  # Tag_CPU_name
                                name_len = payload[i]
                                i += 1
                                if i + name_len <= len(payload):
                                    arch_name = payload[i:i+name_len].decode('ascii', errors='ignore')
                                    i += name_len
                            elif attr_tag == 36:  # Tag_FP_arch (VFP version)
                                fp_val = payload[i]
                                i += 1
                                # 0=No VFP, 1=VFPv1, 2=VFPv2, 3=VFPv3, 4=VFPv3-D16, 5=VFPv4, 6=VFPv4-D16
                                has_fpu = (fp_val > 0)
                            else:
                                i += 1  # skip unknown tag
                    pos += sub_len

                # Heuristic: search for FPU-related symbol if build attr approach failed
                if not arch_name or arch_name == 'Unknown':
                    # Look for FPU init symbol common in STM32 projects
                    if self._symtab:
                        for sym in self._symtab.iter_symbols():
                            name = sym.name
                            if 'FPU' in name and ('SCB' in name or 'CPACR' in name):
                                has_fpu = True
                                break
            except Exception:
                pass

        # Keil AXF 常省略 .ARM.attributes 和浮点 ABI e_flags。此时从函数机器码
        # 中查找实际 VFP 指令；只要固件生成了 VFP 指令，任务上下文就必须按
        # 浮点扩展帧保守估算。
        if not has_fpu and _capstone_available and self._symtab:
            vfp_mnemonics = {
                'vabs', 'vadd', 'vcmp', 'vcmpe', 'vcvt', 'vdiv', 'vldr',
                'vmaxnm', 'vminnm', 'vmla', 'vmls', 'vmov', 'vmul', 'vneg',
                'vnmla', 'vnmls', 'vnmul', 'vpop', 'vpush', 'vsqrt', 'vstr',
                'vsub',
            }
            disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
            for sym in self._symtab.iter_symbols():
                if sym['st_info']['type'] != 'STT_FUNC' or sym['st_size'] <= 0:
                    continue
                address = sym['st_value'] & ~1
                code = self._read_bytes(address, sym['st_size'])
                if not code:
                    continue
                try:
                    if any(insn.mnemonic.split('.')[0] in vfp_mnemonics
                           for insn in disassembler.disasm(code, address)):
                        return True, "VFP instructions detected"
                except Exception:
                    continue

        return has_fpu, arch_name

    def _decode_bl_instructions_indirect(self, data: bytes, base_addr: int) -> int:
        """
        统计函数机器码中 BLX Rn（32位寄存器间接调用指令）的条数。

        检测模式:
          BLX reg: first halfword bits[15:8]=0x47, bits[7]=0 (0x4780..0x47FF)
          BLX.W reg: 32-bit encoding 0xE800 0xC000+  (ThumbEE / ARM)

        @param data:      函数机器码字节
        @param base_addr: 函数起始虚拟地址（已清除 Thumb 位）
        @return: 间接调用（BLX Rn）条数
        """
        count = 0
        offset = 0
        while offset + 1 < len(data):
            hw = struct.unpack_from('<H', data, offset)[0]

            # BLX Rn (16-bit): 0b01000111_1xxx_xnnn (0x4780..0x47FF)
            if (hw & 0xFF80) == 0x4780:
                count += 1
                offset += 2
                continue

            # 32-bit Thumb-2
            is_32bit = (hw >> 11) >= 0x1D
            if is_32bit and offset + 3 < len(data):
                hw2 = struct.unpack_from('<H', data, offset + 2)[0]
                # LDR.W PC, ...  indirect tail-call
                if (hw & 0xF800) == 0xF000 and (hw2 & 0xD000) == 0xC000:
                    count += 1
                offset += 4
            else:
                offset += 2

        return count

    def analyze_stack_depth(self, func_name: str,
                            config: StackDepthConfig = None) -> StackDepthNode | None:
        """
        递归分析函数的调用链最大栈深度。

        从指定函数出发，解码所有 BL 指令找到被调用函数，
        递归分析每个被调用函数的栈帧，累加得到最深路径的栈深度。

        @param func_name:           入口函数名
        @return: StackDepthNode 树根节点，None 表示未找到函数
        """
        sym = self.get_symbol(func_name)
        if not sym or sym['st_info']['type'] != 'STT_FUNC':
            return None

        self._build_addr_to_name_map()

        # 初始化配置
        if config is None:
            config = StackDepthConfig()

        def _analyze_recursive(name: str, active_path: frozenset[int]) -> StackDepthNode:
            sym_info = self.get_symbol(name)
            if not sym_info:
                return StackDepthNode(func_name=name, address=0, own_frame=0, is_leaf=True)

            addr = sym_info['st_value'] & ~1
            size = sym_info['st_size']

            # 分析自身栈帧
            frame = self.analyze_stackframe(name)
            own_frame = frame.stack_frame if frame else 0
            frame_source = frame.source if frame else "unknown"

            # 仅按当前调用路径断环，共享子调用仍需在每条路径上完整计算。
            if addr in active_path:
                return StackDepthNode(
                    func_name=name, address=addr, own_frame=own_frame,
                    cumulative_depth=0, is_leaf=True, is_cycle=True,
                    frame_source=frame_source,
                )
            if size <= 0:
                return StackDepthNode(
                    func_name=name, address=addr, own_frame=own_frame,
                    cumulative_depth=own_frame, is_leaf=True,
                    frame_source=frame_source,
                )

            next_path = active_path | {addr}

            # 读取机器码并解码 BL 调用 + 间接调用计数
            raw_data = self._read_bytes(addr, size)
            indirect_count = 0
            children = []
            if raw_data:
                indirect_count = self._decode_bl_instructions_indirect(raw_data, addr)
                bl_targets = self._decode_bl_instructions(raw_data, addr)
                # 去重：同一函数只分析一次（同深度）
                seen_targets = set()
                for target_addr, target_name in bl_targets:
                    if target_name and target_name not in seen_targets:
                        seen_targets.add(target_name)
                        child = _analyze_recursive(target_name, next_path)
                        children.append(child)

            # 同一函数内的间接调用点通常顺序执行，最大栈深只计一次未知调用开销。
            indirect_penalty = config.indirect_penalty if indirect_count > 0 else 0
            if children:
                max_child = max(children, key=lambda c: c.cumulative_depth)
                cumulative = own_frame + indirect_penalty + max_child.cumulative_depth
                total_indirect = (1 if indirect_count > 0 else 0) + max_child.total_indirect_count
            else:
                cumulative = own_frame + indirect_penalty
                total_indirect = 1 if indirect_count > 0 else 0

            return StackDepthNode(
                func_name=name, address=addr, own_frame=own_frame,
                cumulative_depth=cumulative,
                indirect_count=indirect_count,
                total_indirect_count=total_indirect,
                is_leaf=(len(children) == 0),
                frame_source=frame_source,
                children=children,
            )

        return _analyze_recursive(func_name, frozenset())

    def audit_tasks(self, manifest: dict, project_root: Path) -> dict:
        """Audit an explicit task inventory; unresolved evidence never means safe."""
        if manifest.get('schema_version') != 2:
            raise ValueError('schema_version=2 is required')
        allocation_policy = manifest.get('allocation_policy', {})
        unit_name = allocation_policy.get('unit_name')
        unit_bytes = allocation_policy.get('unit_bytes')
        minimum_units = allocation_policy.get('minimum_units', 0)
        granularity_units = allocation_policy.get('granularity_units', 1)
        if not isinstance(unit_name, str) or not unit_name:
            raise ValueError('allocation_policy.unit_name is required')
        for name, value in (('unit_bytes', unit_bytes),
                            ('minimum_units', minimum_units),
                            ('granularity_units', granularity_units)):
            if type(value) is not int or value < 0:
                raise ValueError(f'allocation_policy.{name} must be a nonnegative integer')
        if unit_bytes == 0 or granularity_units == 0:
            raise ValueError('unit_bytes and granularity_units must be positive')
        context = manifest.get('context', {})
        context_bytes = context.get('bytes')
        if type(context_bytes) is not int or context_bytes < 0 or not context.get('evidence'):
            raise ValueError('context requires nonnegative bytes and evidence')
        factor = manifest.get('safety_factor', 1.5)
        penalty = manifest.get('indirect_penalty_bytes', 80)
        if type(penalty) is not int or penalty < 0:
            raise ValueError('indirect_penalty_bytes must be nonnegative')
        tasks = manifest.get('tasks')
        if not isinstance(tasks, list) or not tasks:
            raise ValueError('tasks must be a nonempty list')
        entries = [task['entry'] for task in tasks]
        if len(set(entries)) != len(entries):
            raise ValueError('duplicate task entries')
        config = StackDepthConfig(indirect_penalty=penalty,
                      context_bytes=context_bytes,
                      safety_factor=factor)
        cached_roots = {}
        inspected = {}

        def analyze(name):
            if name not in cached_roots:
                cached_roots[name] = self.analyze_stack_depth(name, config=config)
            return cached_roots[name]

        def code_issues(name):
            if name in inspected:
                return inspected[name]
            issues = set()
            symbols = self._symtab.get_symbol_by_name(name) if self._symtab else []
            if len(symbols or []) > 1:
                issues.add('ambiguous_symbol:' + name)
            symbol = self.get_symbol(name)
            if not symbol or symbol['st_size'] <= 0:
                issues.add('missing_code:' + name)
            else:
                address = symbol['st_value'] & ~1
                data = self._read_bytes(address, symbol['st_size'])
                if not data or len(data) != symbol['st_size']:
                    issues.add('incomplete_code:' + name)
                elif not (symbol['st_value'] & 1):
                    issues.add('unsupported_arm_mode:' + name)
                else:
                    for target, target_name in self._decode_bl_instructions(data, address):
                        if not target_name:
                            issues.add(f'unresolved_direct:{name}:0x{target:x}')
                    if _capstone_available:
                        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
                        decoded = list(decoder.disasm(data, address))
                        if sum(instruction.size for instruction in decoded) != len(data):
                            issues.add('incomplete_disassembly:' + name)
                        for instruction in decoded:
                            mnemonic = instruction.mnemonic.split('.')[0]
                            operand = instruction.op_str
                            if mnemonic.startswith('b') and mnemonic not in ('bl', 'blx', 'bic', 'bfi', 'bfc', 'bkpt'):
                                if operand.startswith('#'):
                                    target = int(operand[1:], 0) & ~1
                                    if not address <= target < address + len(data):
                                        issues.add(f'unmodeled_tail_branch:{name}:0x{target:x}')
                                elif mnemonic == 'bx' and operand != 'lr':
                                    issues.add('indirect_tail_branch:' + name)
                    else:
                        issues.add('capstone_unavailable')
            inspected[name] = issues
            return issues

        def collect(root):
            issues = set()
            sources = {}
            indirect = {}
            pending = [root] if root else []
            visited = set()
            while pending:
                node = pending.pop()
                if node.is_cycle:
                    issues.add('cycle:' + node.func_name)
                if node.func_name in visited:
                    continue
                visited.add(node.func_name)
                sources[node.func_name] = node.frame_source
                if node.frame_source != 'dwarf_cfi':
                    issues.add('frame_' + node.frame_source + ':' + node.func_name)
                if node.indirect_count:
                    indirect[node.func_name] = node.indirect_count
                    issues.add('unresolved_indirect:' + node.func_name)
                issues.update(code_issues(node.func_name))
                pending.extend(node.children)
            return issues, sources, indirect

        def deepest(root):
            path = []
            while root:
                path.append(root.func_name)
                root = max(root.children, key=lambda child: child.cumulative_depth) if root.children else None
            return path

        rows = []
        for task in tasks:
            entry = task['entry']
            allocated = task['allocated_units']
            calculate_stack_budget(0, context_bytes, allocated, unit_bytes,
                                   minimum_units, granularity_units, factor)
            issues = set()
            allocation = task.get('allocation', {})
            source = project_root / allocation.get('file', '')
            macro = allocation.get('macro', '')
            if not source.is_file() or not macro:
                issues.add('allocation_unverified')
            else:
                text = source.read_text(encoding='utf-8-sig')
                values = re.findall(r'^\s*#define\s+' + re.escape(macro)
                                    + r'\s+\(?\s*(\d+)[uUlL]*\s*\)?\s*(?:(?:/[/\*]).*)?$',
                                    text, re.MULTILINE)
                if len(values) != 1 or int(values[0]) != allocated:
                    issues.add('allocation_mismatch_or_expression:' + macro)
                if source.stat().st_mtime > Path(self.path).stat().st_mtime:
                    issues.add('allocation_source_newer_than_axf')
            root = analyze(entry)
            if root is None:
                rows.append({'entry': entry, 'allocated_units': allocated,
                             'status': 'MISSING_SYMBOL', 'issues': sorted(issues | {'missing_symbol:' + entry})})
                continue
            root_issues, sources, indirect = collect(root)
            issues.update(root_issues)
            modeled = root.cumulative_depth
            selected_path = deepest(root)
            callback_results = []
            for callback in task.get('callback_paths', []):
                path = callback.get('path', [])
                if not path or path[0] != entry or not callback.get('evidence'):
                    raise ValueError(f'{entry}: callback path must start at task and include evidence')
                if len(set(path)) != len(path):
                    raise ValueError(f'{entry}: recursive callback path is not bounded')
                prefix_bytes = 0
                usable = True
                for name in path[:-1]:
                    frame = self.analyze_stackframe(name)
                    if frame is None:
                        issues.add('missing_callback_symbol:' + name)
                        usable = False
                        continue
                    prefix_bytes += frame.stack_frame
                    sources[name] = frame.source
                    issues.update(code_issues(name))
                    if frame.source != 'dwarf_cfi':
                        issues.add('frame_' + frame.source + ':' + name)
                target = analyze(path[-1])
                if target is None:
                    issues.add('missing_callback_symbol:' + path[-1])
                    usable = False
                if not usable:
                    continue
                target_issues, target_sources, target_indirect = collect(target)
                issues.update(target_issues)
                sources.update(target_sources)
                indirect.update(target_indirect)
                candidate = prefix_bytes + target.cumulative_depth
                callback_results.append({'path': path, 'modeled_bytes': candidate,
                                         'evidence': callback['evidence']})
                if candidate > modeled:
                    modeled = candidate
                    selected_path = path[:-1] + deepest(target)
            budget = calculate_stack_budget(modeled, context_bytes, allocated, unit_bytes,
                                            minimum_units, granularity_units, factor)
            status = 'MODEL_OVER_BUDGET' if budget['model_exceeds_allocation'] else 'NEEDS_RUNTIME_CHECK'
            if issues and status != 'MODEL_OVER_BUDGET':
                status = 'INCOMPLETE'
            rows.append({
                'entry': entry, **budget, 'status': status,
                'direct_model_bytes': root.cumulative_depth,
                'deepest_path': selected_path, 'callback_paths': callback_results,
                'frame_sources': sources, 'indirect_sites_by_function': indirect,
                'indirect_sites_all_branches': sum(indirect.values()),
                'issues': sorted(issues), 'allocation': allocation,
            })
        rows.sort(key=lambda row: row.get('required_ratio', float('inf')), reverse=True)
        return {
            'schema_version': 2, 'axf': str(Path(self.path).resolve()),
            'axf_sha256': hashlib.sha256(Path(self.path).read_bytes()).hexdigest(),
            'context': context, 'allocation_policy': allocation_policy,
            'safety_factor': factor,
            'inventory_notes': manifest.get('inventory_notes', []),
            'indirect_penalty_bytes': penalty,
            'limitations': [
                'Inventory is explicit, not automatically proven complete or matched to the binary.',
                'CFI is unwind metadata, not a proof of maximum stack usage.',
                'BL-only graph: tail calls, indirect targets and dynamic SP may be missing.',
                'Callback paths are user-supplied evidence, not verified call-site SP bounds.',
                'No SAFE verdict: validate PSP high-water marks and MSP separately on hardware.',
            ],
            'tasks': rows,
        }

    @staticmethod
    def format_task_audit(report: dict) -> str:
        """Render a compact table; JSON remains the authoritative detailed report."""
        lines = [f"AXF SHA256: {report['axf_sha256']}",
                 f"Context: {report['context']['bytes']} B ({report['context']['evidence']})",
                 f"Allocation unit: {report['allocation_policy']['unit_name']} = "
                 f"{report['allocation_policy']['unit_bytes']} B",
                 'Task                     Alloc(U) Model(B) Need(B) Rec(U) Need/Alloc Status']
        for row in report['tasks']:
            if 'required_bytes' not in row:
                lines.append(f"{row['entry']:<24} {row['allocated_units']:>8} MISSING_SYMBOL")
                continue
            lines.append(f"{row['entry']:<24} {row['allocated_units']:>8} "
                         f"{row['modeled_bytes']:>8} {row['required_bytes']:>7} "
                         f"{row['recommended_units']:>6} {row['required_ratio']:>10.1%} {row['status']}")
            lines.append('  Path: ' + ' > '.join(row['deepest_path']))
            if row['issues']:
                lines.append('  Gaps: ' + '; '.join(row['issues'][:5]) +
                             ('; ... (use --json)' if len(row['issues']) > 5 else ''))
            lines.append(f"  Indirect sites (all branches): {row['indirect_sites_all_branches']}; "
                         f"evidence gaps: {len(row['issues'])}")
        lines.extend('WARNING: ' + warning for warning in report['limitations'])
        return '\n'.join(lines)

    def format_stack_depth_tree(self, root: StackDepthNode,
                                 config: StackDepthConfig = None,
                                 max_children_display: int = 8) -> str:
        """
        将栈深度分析树格式化为人类可读的文本，包含分项 breakdown。

        @param root:                 根节点
        @param config:              估算配置（用于 breakdown）
        @param max_children_display: 每层最多显示的子节点数
        @return: 格式化文本
        """
        if config is None:
            config = StackDepthConfig()

        ctx_frame = config.context_bytes
        ctx_source = "用户指定" if ctx_frame > 0 else "未计入；由目标架构与执行模型的证据决定"

        # 分项计算
        static_depth = root.cumulative_depth - (root.total_indirect_count * config.indirect_penalty)
        indirect_total = root.total_indirect_count * config.indirect_penalty
        base_total = root.cumulative_depth + ctx_frame
        recommended_b = math.ceil(base_total * config.safety_factor)

        def _contains_cycle(node: StackDepthNode) -> bool:
            return node.is_cycle or any(_contains_cycle(child) for child in node.children)

        has_cycle = _contains_cycle(root)

        lines = [
            f"\n调用链栈深度分析: {root.func_name}",
            "=" * 70,
            f"  入口函数自身栈帧: {root.own_frame}B",
            f"  静态调用链累计深度: {static_depth}B",
            f"  调用链深度限制: 无（按当前路径检测调用环）",
            f"  最深路径间接调用层数: {root.total_indirect_count}",
            "",
            "调用链树 (每行: 函数名 [自身栈帧, 累计栈深度]):",
            "-" * 70,
        ]

        # 标记最深路径
        def _mark_deepest_path(node: StackDepthNode):
            """标记最深子节点路径"""
            if not node.children:
                return
            max_child = max(node.children, key=lambda c: c.cumulative_depth)
            max_child._is_deepest = True
            for child in node.children:
                _mark_deepest_path(child)

        root._is_deepest = True
        _mark_deepest_path(root)

        def _print_node(node: StackDepthNode, indent: str, is_last: bool, is_root: bool = False):
            marker = "← 最深路径" if getattr(node, '_is_deepest', False) else ""
            leaf_mark = " [调用环，停止展开]" if node.is_cycle else (" [叶子]" if node.is_leaf else "")
            indirect_mark = f" [间接:{node.indirect_count}]" if node.indirect_count > 0 else ""
            source_mark = " [前言估算]" if node.frame_source == "prologue" else (" [栈帧未知]" if node.frame_source == "unknown" else "")
            branch = "└─" if is_last else "├─"
            if is_root:
                line = f"{node.func_name} [自身:{node.own_frame}B, 累计:{node.cumulative_depth}B]{source_mark}{indirect_mark} {marker}"
            else:
                line = f"{indent}{branch} {node.func_name} [自身:{node.own_frame}B, 累计:{node.cumulative_depth}B]{source_mark}{leaf_mark}{indirect_mark} {marker}"
            lines.append(line)

            if node.children:
                child_indent = indent + ("   " if is_last else "│  ")
                sorted_children = sorted(node.children, key=lambda c: c.cumulative_depth, reverse=True)
                display_children = sorted_children[:max_children_display]
                for i, child in enumerate(display_children):
                    is_last_child = (i == len(display_children) - 1)
                    _print_node(child, child_indent, is_last_child)

                if len(sorted_children) > max_children_display:
                    lines.append(f"{child_indent}└─ ... 还有 {len(sorted_children) - max_children_display} 个被调用函数")

        _print_node(root, "", True, is_root=True)
        lines.append("")
        lines.append("-" * 70)
        lines.append("分项 Breakdown:")
        lines.append(f"  静态 BL 直接调用链:      {static_depth}B")
        lines.append(f"  间接调用(BLX Rn) 估算:   {indirect_total}B  ({root.total_indirect_count} 层 × {config.indirect_penalty}B/层)")
        lines.append(f"  调度/异常上下文预算:    {ctx_frame}B  ({ctx_source})")
        lines.append(f"  {('─' * 45)}")
        lines.append(f"  基准合计:                {base_total}B")
        lines.append(f"  × 安全系数 {config.safety_factor}:          {recommended_b}B")
        if has_cycle:
            lines.append("  警告: 检测到递归调用环；当前为截环模型值，不能证明真实上界或下界")
        lines.append("")
        lines.append(f"  → 含安全系数模型需求:    {recommended_b}B")
        lines.append("  未换算分配单位/最小值/对齐；批量审计请使用目标项目的 manifest。")
        return '\n'.join(lines)

    # ============================================================
    # --addr2line / --callstack (阶段3)
    # ============================================================

    def addr2line(self, addr: int, max_inline_depth: int = 20) -> list[InlineFrame]:
        """
        地址转源码位置，包含内联调用链展开。
        返回调用链列表，从最外层到最内层。
        """
        if not self._has_debug_info:
            return []

        frames = []
        self._find_inline_chain(addr, frames, max_inline_depth, 0)
        return frames

    def _find_inline_chain(self, addr: int, frames: list, max_depth: int, current_depth: int):
        """递归查找内联调用链"""
        if current_depth >= max_depth:
            return

        for cu in self._dwarf_info.iter_CUs():
            lineprog = self._dwarf_info.line_program_for_CU(cu)
            if not lineprog:
                continue

            # 查找地址所在的行号条目
            prev_state = None
            matched_state = None
            for entry in lineprog.get_entries():
                state = entry.state
                if state is None:
                    continue
                if prev_state and prev_state.address <= addr < state.address:
                    matched_state = prev_state
                    break
                prev_state = state

            # 处理最后一个条目之后的情况
            if matched_state is None and prev_state and prev_state.address <= addr:
                matched_state = prev_state

            if matched_state is None:
                continue

            file_entry = lineprog.header.file_entry[matched_state.file - 1]
            filepath = file_entry.name.decode('utf-8', errors='replace') if isinstance(file_entry.name, bytes) else str(file_entry.name)
            directory = lineprog.header.include_directory[file_entry.dir_index - 1] if file_entry.dir_index > 0 else b'.'
            if isinstance(directory, bytes):
                directory = directory.decode('utf-8', errors='replace')
            full_path = os.path.normpath(os.path.join(directory, filepath)).replace('\\', '/')

            frame = InlineFrame(
                file=full_path,
                line=matched_state.line,
                column=matched_state.column if matched_state.column else 0,
            )
            frames.append(frame)

            # 内联展开：查找该地址的 DW_TAG_inlined_subroutine
            self._expand_inline(addr, cu, frame, frames, max_depth, current_depth)
            return  # 找到对应的 CU 后返回

    def _expand_inline(self, addr: int, cu, frame: InlineFrame, frames: list, max_depth: int, current_depth: int):
        """在指定 CU 的 DIE 树中展开内联调用"""
        top_die = cu.get_top_DIE()
        self._search_inline_die(top_die, cu, addr, frames, max_depth, current_depth + 1)

    def _search_inline_die(self, die, cu, addr: int, frames: list, max_depth: int, depth: int):
        """递归搜索 DW_TAG_inlined_subroutine"""
        if depth >= max_depth:
            return

        for child in die.iter_children():
            if child.tag == 'DW_TAG_inlined_subroutine':
                # 检查内联地址范围
                low_pc = child.attributes.get('DW_AT_low_pc')
                high_pc = child.attributes.get('DW_AT_high_pc')

                if low_pc and high_pc:
                    low = low_pc.value if not isinstance(low_pc.value, (list, tuple)) else low_pc.value[0]
                    high = high_pc.value if not isinstance(high_pc.value, (list, tuple)) else high_pc.value[0]
                    if isinstance(high, int) and high < 0x10000:
                        # high_pc 可能是偏移量
                        if isinstance(low, int):
                            high = low + high
                    if isinstance(low, int) and isinstance(high, int) and low <= addr < high:
                        # 获取内联函数信息
                        inline_frame = InlineFrame(file='', line=0)
                        abs_origin = child.attributes.get('DW_AT_abstract_origin')
                        if abs_origin:
                            resolved = self._resolve_die_ref(cu, abs_origin.value)
                            if resolved:
                                name = resolved.attributes.get('DW_AT_name')
                                if name:
                                    inline_frame.function = name.value.decode('utf-8', errors='replace') if isinstance(name.value, bytes) else str(name.value)
                                decl_file = resolved.attributes.get('DW_AT_decl_file')
                                decl_line = resolved.attributes.get('DW_AT_decl_line')
                                if decl_file and decl_line:
                                    inline_frame.line = decl_line.value
                                    inline_frame.file = self._resolve_file_name(cu, decl_file.value)

                        call_file = child.attributes.get('DW_AT_call_file')
                        call_line = child.attributes.get('DW_AT_call_line')
                        if call_file and call_line:
                            inline_frame.file = self._resolve_file_name(cu, call_file.value)
                            inline_frame.line = call_line.value

                        if inline_frame.file:
                            frames.append(inline_frame)
                            self._search_inline_die(child, cu, addr, frames, max_depth, depth + 1)
                            return

            # 继续递归搜索
            self._search_inline_die(child, cu, addr, frames, max_depth, depth)

    def _resolve_die_ref(self, cu, offset: int):
        """通过 DIE offset 解析引用"""
        try:
            return cu.get_DIE_from_attribute('DW_AT_abstract_origin',
                  self._dwarf_info.get_DIE_from_refaddr(offset))
        except Exception:
            pass
        # 尝试在当前 CU 中查找
        try:
            for die in cu.get_top_DIE().iter_children():
                if die.offset == offset:
                    return die
        except Exception:
            pass
        return None

    def _resolve_file_name(self, cu, file_index: int) -> str:
        """通过文件索引解析文件名"""
        try:
            lineprog = self._dwarf_info.line_program_for_CU(cu)
            if lineprog and 0 < file_index <= len(lineprog.header.file_entry):
                entry = lineprog.header.file_entry[file_index - 1]
                name = entry.name.decode('utf-8', errors='replace') if isinstance(entry.name, bytes) else str(entry.name)
                directory = lineprog.header.include_directory[entry.dir_index - 1] if entry.dir_index > 0 else b'.'
                if isinstance(directory, bytes):
                    directory = directory.decode('utf-8', errors='replace')
                return os.path.normpath(os.path.join(directory, name)).replace('\\', '/')
        except Exception:
            pass
        return str(file_index)

    # ============================================================
    # --struct (阶段4)
    # ============================================================

    def get_struct_layout(self, struct_name: str, expand: bool = False) -> list[Member]:
        """获取结构体/联合体布局"""
        if not self._has_debug_info:
            sys.exit(
                "错误: 缺少 DWARF 调试信息。\n"
                "  --struct 需要 .axf 包含 .debug_info 节，请在编译时添加 -g 选项。"
            )

        for cu in self._dwarf_info.iter_CUs():
            top_die = cu.get_top_DIE()
            result = self._find_struct_die(top_die, cu, struct_name, expand)
            if result:
                return result
        return []

    def get_struct_byte_size(self, struct_name: str) -> int:
        """返回结构体/联合体的总字节大小（DW_AT_byte_size）；找不到返回 0。

        旧版 --struct 只列成员、不给总大小，用户仍需手工累加 padding。
        """
        if not self._has_debug_info:
            return 0
        for cu in self._dwarf_info.iter_CUs():
            die = self._find_struct_die_by_name(cu.get_top_DIE(), struct_name)
            if die is not None:
                sz = die.attributes.get('DW_AT_byte_size')
                if sz:
                    return sz.value
        return 0

    def _find_struct_die_by_name(self, die, name: str):
        """搜索带 byte_size 的结构体/联合体 DIE（跳过前置声明）。"""
        if die.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
            n = die.attributes.get('DW_AT_name')
            if n:
                val = n.value.decode('utf-8', errors='replace') \
                    if isinstance(n.value, bytes) else str(n.value)
                if val == name and 'DW_AT_byte_size' in die.attributes:
                    return die
        if die.tag == 'DW_TAG_subprogram':
            return None
        if die.tag == 'DW_TAG_typedef':
            n = die.attributes.get('DW_AT_name')
            if n:
                val = n.value.decode('utf-8', errors='replace') \
                    if isinstance(n.value, bytes) else str(n.value)
                if val == name:
                    target = self._get_type_die(die)
                    if target is not None:
                        sz = target.attributes.get('DW_AT_byte_size')
                        if sz:
                            return target
        for child in die.iter_children():
            r = self._find_struct_die_by_name(child, name)
            if r is not None:
                return r
        return None

    def _find_struct_die(self, die, cu, name: str, expand: bool) -> list[Member] | None:
        """在 DIE 树中搜索匹配名称的结构体/联合体"""
        tag_name = die.tag
        if tag_name in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
            die_name = die.attributes.get('DW_AT_name')
            if die_name:
                die_name_val = die_name.value.decode('utf-8', errors='replace') if isinstance(die_name.value, bytes) else str(die_name.value)
                if die_name_val == name:
                    return self._parse_members(die, cu, expand)

        # 不搜索 DW_TAG_subprogram 之下
        if die.tag == 'DW_TAG_subprogram':
            return None

        # typedef：`typedef struct {...} DeviceInfo_t;` 的真实结构体 DIE 往往
        # 没有名字（匿名），只能通过 typedef 名命中后跟随 DW_AT_type。
        if die.tag == 'DW_TAG_typedef':
            die_name = die.attributes.get('DW_AT_name')
            if die_name:
                val = die_name.value.decode('utf-8', errors='replace') \
                    if isinstance(die_name.value, bytes) else str(die_name.value)
                if val == name:
                    target = self._get_type_die(die)
                    if target is not None and target.tag in ('DW_TAG_structure_type',
                                                             'DW_TAG_union_type'):
                        return self._parse_members(target, cu, expand)

        for child in die.iter_children():
            result = self._find_struct_die(child, cu, name, expand)
            if result:
                return result
        return None

    def _parse_members(self, die, cu, expand: bool, depth: int = 0) -> list[Member]:
        """解析结构体成员"""
        members = []
        for child in die.iter_children():
            if child.tag != 'DW_TAG_member' and child.tag != 'DW_TAG_inheritance':
                continue

            member_name = child.attributes.get('DW_AT_name')
            if member_name:
                member_name = member_name.value.decode('utf-8', errors='replace') if isinstance(member_name.value, bytes) else str(member_name.value)
            else:
                member_name = '<anonymous>'

            # 类型（DWARF 的 DW_AT_type 是引用，必须先解引用才有 attributes；
            # 原实现直接读 .value，导致所有成员都退化成 <unknown>）
            type_name = '<unknown>'
            member_size = 0
            nested_children = []

            try:
                type_die = child.get_DIE_from_attribute('DW_AT_type') \
                    if 'DW_AT_type' in child.attributes else None
                if type_die is not None:
                    type_name, member_size = self._type_display(type_die)
                    if expand and type_die.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
                        nested_children = self._parse_members(type_die, cu, expand, depth + 1)
            except Exception:
                type_name = '<unresolved>'

            # 偏移
            offset = child.attributes.get('DW_AT_data_member_location')
            if offset:
                try:
                    if hasattr(offset.value, '__iter__') and not isinstance(offset.value, (str, bytes)):
                        # DWARF expression, 通常是简单常量
                        val = offset.value
                        if isinstance(val, (list, tuple)) and len(val) > 0:
                            block = val
                            if block[0] == 0x23 and len(block) >= 2:  # OP_plus_uconst
                                offset_val = block[1]
                            elif block[0] == 0x55 and len(block) >= 2:  # OP_reg0
                                offset_val = 0
                            else:
                                offset_val = 0
                        else:
                            offset_val = 0
                    else:
                        offset_val = int(offset.value)
                except Exception:
                    offset_val = 0
            else:
                offset_val = 0

            # 位域
            bit_offset = -1
            bit_size = 0
            bo = child.attributes.get('DW_AT_bit_offset')
            bs = child.attributes.get('DW_AT_bit_size')
            if bs:
                bit_size = bs.value
                if bo:
                    bit_offset = bo.value

            members.append(Member(
                name=member_name,
                type_name=type_name,
                offset=offset_val,
                size=member_size,
                bit_offset=bit_offset,
                bit_size=bit_size,
                children=nested_children,
            ))

        return members

    @staticmethod
    def _get_type_die(die):
        """解引用 DW_AT_type，返回类型 DIE（失败返回 None）。"""
        if die is None or 'DW_AT_type' not in die.attributes:
            return None
        try:
            return die.get_DIE_from_attribute('DW_AT_type')
        except Exception:
            return None

    def _type_display(self, die, depth: int = 0):
        """把类型 DIE 渲染成可读类型名，并返回字节大小。

        支持 pointer / array / const / volatile / typedef 的递归展开，
        解决旧实现把所有成员类型显示为 `<unknown>` 的问题。
        """
        if die is None or depth > 8:
            return '<unknown>', 0

        tag = die.tag
        size_attr = die.attributes.get('DW_AT_byte_size')
        size = size_attr.value if size_attr else 0

        name = None
        name_attr = die.attributes.get('DW_AT_name')
        if name_attr:
            name = name_attr.value.decode('utf-8', errors='replace') \
                if isinstance(name_attr.value, bytes) else str(name_attr.value)

        if tag == 'DW_TAG_pointer_type':
            inner, _ = self._type_display(self._get_type_die(die), depth + 1)
            return f"{inner} *", size or 4

        if tag == 'DW_TAG_array_type':
            inner, _ = self._type_display(self._get_type_die(die), depth + 1)
            count = 0
            for ch in die.iter_children():
                if ch.tag == 'DW_TAG_subrange_type':
                    c = ch.attributes.get('DW_AT_count') \
                        or ch.attributes.get('DW_AT_upper_bound')
                    if c is not None:
                        count = c.value
            return f"{inner}[{count}]", size

        if tag in ('DW_TAG_const_type', 'DW_TAG_volatile_type',
                   'DW_TAG_restrict_type', 'DW_TAG_typedef'):
            inner, inner_size = self._type_display(self._get_type_die(die), depth + 1)
            if tag == 'DW_TAG_const_type':
                inner = f"const {inner}"
            return inner, size or inner_size

        if name:
            return name, size
        if tag == 'DW_TAG_structure_type':
            return f'struct<{size}B>', size
        if tag == 'DW_TAG_union_type':
            return f'union<{size}B>', size
        return '<unknown>', size

    # ============================================================
    # --unused（死符号候选）
    # ============================================================

    def get_unused_symbols(self, min_size: int = 0,
                           include_funcs: bool = False) -> list[SymbolInfo]:
        """列出“已定义但看起来从未被引用”的符号候选（best-effort）。

        判定方法：
          1. 扫描所有 SHF_ALLOC 节的原始字节，把每个 4 字节小端字视为可能指针；
             函数按 **Thumb 位掩码**（addr & ~1）比对 —— Cortex-M 的函数指针
             最低位恒为 1，直接比原始值会把所有任务入口误判为“未引用”；
          2. 若 capstone 可用，再反汇编所有函数，收集 BL/BLX 立即数目标。

        同时排除：以下划线开头的链接脚本/运行时符号、无 SHF_ALLOC 的调试符号。

        @warning 这是**候选列表**，不是“可安全删除”的结论：调试信息引用、
                 链接脚本引用（如 __initial_sp）以及未识别的间接跳转都可能
                 让一个实际在用的符号看起来“无人引用”。
        """
        import bisect

        if not self._symtab:
            return []

        func_keys = {}          # (addr & ~1) -> (name, size)
        obj_ranges = []         # (start, end, name) 升序
        cands = []              # (addr, size, name, type, region)

        for sym in self._symtab.iter_symbols():
            st_type = sym['st_info']['type']
            if st_type not in ('STT_FUNC', 'STT_OBJECT'):
                continue
            size = sym['st_size']
            if size <= 0 or size < min_size:
                continue
            name = sym.name
            # 排除链接脚本符号（_xxx）、汇编局部标签/字面量（.L.str.* 等以 '.' 开头）
            if not name or name.startswith(('_', '$', '.')):
                continue
            if sym['st_shndx'] == 'SHN_UNDEF':
                continue
            region = self._section_region(sym)
            if region == 'OTHER':
                continue
            if st_type == 'STT_FUNC':
                # 函数始终登记（供 BL/movw 目标解析），但默认不作为"未引用"报告：
                # 函数指针派发/尾调用/零长度符号会让函数级死代码判定不可靠。
                func_keys[sym['st_value'] & ~1] = name
                if not include_funcs:
                    continue
            else:
                obj_ranges.append((sym['st_value'], sym['st_value'] + size, name))
            cands.append((sym['st_value'], size, name, st_type, region))

        if not cands:
            return []

        obj_ranges.sort()
        obj_starts = [r[0] for r in obj_ranges]
        referenced = set()

        def mark_word(word: int) -> None:
            # 函数：按 Thumb 位归一后精确匹配入口地址
            hit = func_keys.get(word & ~1)
            if hit is not None:
                referenced.add(hit)
            # 数据对象：允许指向对象内部的指针
            idx = bisect.bisect_right(obj_starts, word) - 1
            if idx >= 0 and obj_ranges[idx][0] <= word < obj_ranges[idx][1]:
                referenced.add(obj_ranges[idx][2])

        # 1) 所有 SHF_ALLOC 节里的指针字
        for sec in self._elffile.iter_sections():
            try:
                flags = sec['sh_flags']
                stype = sec['sh_type']
            except Exception:
                continue
            if not (flags & 0x2):            # SHF_ALLOC
                continue
            if stype not in ('SHT_PROGBITS', 'SHT_INIT_ARRAY',
                             'SHT_FINI_ARRAY', 'SHT_PREINIT_ARRAY'):
                continue
            try:
                data = sec.data()
            except Exception:
                continue
            for off in range(0, len(data) - 3, 4):
                mark_word(struct.unpack_from('<I', data, off)[0])

        # 2) 函数里的 BL/BLX 立即数目标 + movw/movt 合成的地址常量
        #    （Keil/ARMClang 常用 `movw rX,#lo; movt rX,#hi` 装载地址，
        #     此时地址不会以 4 字节字面量出现在任何节里，必须从指令解码）
        try:
            from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
            from capstone.arm import ARM_OP_IMM, ARM_OP_REG

            md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
            md.detail = True
            for sym in self._symtab.iter_symbols():
                if sym['st_info']['type'] != 'STT_FUNC' or sym['st_size'] == 0:
                    continue
                base = sym['st_value'] & ~1
                data = self._read_bytes(base, sym['st_size'])
                if not data:
                    continue
                movw_regs = {}
                for ins in md.disasm(data, base):
                    ops = ins.operands
                    if ins.mnemonic in ('bl', 'blx') and ops \
                            and ops[0].type == ARM_OP_IMM:
                        callee = func_keys.get(ops[0].imm & ~1)
                        if callee:
                            referenced.add(callee)
                    elif ins.mnemonic == 'movw' and len(ops) >= 2 \
                            and ops[0].type == ARM_OP_REG and ops[1].type == ARM_OP_IMM:
                        movw_regs[ops[0].reg] = ops[1].imm & 0xFFFF
                    elif ins.mnemonic == 'movt' and len(ops) >= 2 \
                            and ops[0].type == ARM_OP_REG and ops[1].type == ARM_OP_IMM:
                        low = movw_regs.get(ops[0].reg, 0)
                        mark_word((low & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16))
        except Exception:
            pass

        type_display = {'STT_FUNC': 'FUNC', 'STT_OBJECT': 'OBJECT'}
        unused = [SymbolInfo(name=n, address=a, size=s,
                             st_type=type_display.get(t, t),
                             section='', region=r)
                  for a, s, n, t, r in cands if n not in referenced]
        unused.sort(key=lambda x: x.size, reverse=True)
        return unused

    # ============================================================
    # --disasm (阶段5)
    # ============================================================

    def disassemble_function(self, func_name: str, mixed: bool = False) -> str:
        """反汇编指定函数"""
        sym = self.get_symbol(func_name)
        if not sym:
            return f"错误: 未找到符号 '{func_name}'"

        if sym['st_info']['type'] != 'STT_FUNC':
            return f"错误: 符号 '{func_name}' 不是函数 (type={sym['st_info']['type']})"

        start_addr = sym['st_value']
        size = sym['st_size']
        if size == 0:
            return f"错误: 函数 '{func_name}' 大小为 0，无法反汇编"

        # 检测 Thumb 模式，清除地址最低位
        is_thumb = (start_addr & 1) == 1
        real_addr = start_addr & ~1

        # 从段中读取机器码（使用 real_addr 计算偏移，避免 Thumb 位导致错位）
        try:
            text_data = None
            text_offset = None
            for seg in self._elffile.iter_segments():
                if seg.header.p_vaddr <= real_addr < seg.header.p_vaddr + seg.header.p_filesz:
                    data = seg.data()
                    offset_in_seg = real_addr - seg.header.p_vaddr
                    text_data = data[offset_in_seg:offset_in_seg + size]
                    text_offset = real_addr
                    break

            # fallback: 从 .text 节读取
            if text_data is None:
                text_sec = self.get_section('.text')
                if text_sec and text_sec.header.sh_addr <= real_addr < text_sec.header.sh_addr + text_sec.header.sh_size:
                    data = text_sec.data()
                    offset = real_addr - text_sec.header.sh_addr
                    text_data = data[offset:offset + size]
                    text_offset = real_addr
        except Exception as e:
            return f"错误: 无法读取函数机器码: {e}"

        if not text_data:
            return f"错误: 无法在 ELF 中找到函数 '{func_name}' 的机器码"

        if _capstone_available:
            return self._disasm_capstone(text_data, real_addr, is_thumb, mixed, func_name)
        else:
            return self._disasm_hexdump(text_data, real_addr, is_thumb, func_name)

    def _disasm_capstone(self, data: bytes, addr: int, is_thumb: bool, mixed: bool, func_name: str) -> str:
        """使用 Capstone 反汇编"""
        mode = CS_MODE_THUMB if is_thumb else CS_MODE_ARM
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = True

        lines = []
        lines.append(f"\n; 函数: {func_name} @ 0x{addr:08X}  ({'Thumb' if is_thumb else 'ARM'} mode)")
        lines.append("; " + "-" * 70)

        # 构建混合源码映射
        line_map = {}
        if mixed and self._has_debug_info:
            line_map = self._build_line_address_map(func_name, addr)

        prev_src_line = None
        for insn in md.disasm(data, addr):
            # 混合模式：插入源码行
            if mixed and insn.address in line_map:
                src_info = line_map[insn.address]
                if src_info != prev_src_line:
                    lines.append(f"; --- {src_info}")
                    prev_src_line = src_info

            # 汇编行
            bytes_str = ' '.join(f'{b:02x}' for b in insn.bytes)
            lines.append(f"  0x{insn.address:08X}:  {bytes_str:<20s}  {insn.mnemonic:10s} {insn.op_str}")

        return '\n'.join(lines)

    def _disasm_hexdump(self, data: bytes, addr: int, is_thumb: bool, func_name: str) -> str:
        """十六进制 dump（无 Capstone 时降级）"""
        lines = [
            f"\n [警告] 未安装 capstone，仅显示十六进制 dump。",
            f"  安装后可使用完整反汇编功能: pip install capstone>=4.0",
            f"",
            f"; 函数: {func_name} @ 0x{addr:08X}  ({'Thumb' if is_thumb else 'ARM'} mode, {len(data)} bytes)",
            f"; " + "-" * 70,
        ]

        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"  0x{addr + i:08X}:  {hex_str:<48s}  |{ascii_str}|")

        return '\n'.join(lines)

    def _build_line_address_map(self, func_name: str, func_addr: int) -> dict[int, str]:
        """构建地址到源码行的映射（用于 --mixed 模式）"""
        line_map = {}
        if not self._has_debug_info:
            return line_map

        for cu in self._dwarf_info.iter_CUs():
            lineprog = self._dwarf_info.line_program_for_CU(cu)
            if not lineprog:
                continue

            prev_state = None
            for entry in lineprog.get_entries():
                state = entry.state
                if state is None:
                    continue
                if prev_state and prev_state.address >= func_addr:
                    file_entry = lineprog.header.file_entry[prev_state.file - 1]
                    fname = file_entry.name.decode('utf-8', errors='replace') if isinstance(file_entry.name, bytes) else str(file_entry.name)
                    line_map[prev_state.address] = f"{fname}:{prev_state.line}"
                prev_state = state

        return line_map

    # ============================================================
    # --callgraph (阶段6)
    # ============================================================

    def get_callgraph(self, func_name: str, depth: int = 2) -> str:
        """构建静态调用图（基于重定位表）"""
        target_sym = self.get_symbol(func_name)
        if not target_sym:
            return f"错误: 未找到符号 '{func_name}'"

        target_addr = target_sym['st_value'] & ~1  # 清除 Thumb 标记

        # 构建地址到符号名的映射
        addr_to_name = {}
        if self._symtab:
            for sym in self._symtab.iter_symbols():
                if sym['st_info']['type'] == 'STT_FUNC':
                    addr_to_name[sym['st_value'] & ~1] = sym.name

        # 解析重定位表构建调用图
        caller_map = defaultdict(set)  # callee_addr → set of caller names
        callee_map = defaultdict(set)  # caller_addr → set of callee names

        for sec in self._elffile.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue

            for reloc in sec.iter_relocations():
                rtype = None
                try:
                    rtype = reloc['r_info_type_disp']
                except (KeyError, TypeError):
                    pass
                if not rtype:
                    try:
                        rtype = reloc.entry.r_info_type
                    except Exception:
                        continue

                rtype_str = str(rtype) if not isinstance(rtype, str) else rtype
                if not any(t in rtype_str for t in ('CALL', 'JUMP24', 'THM_CALL', 'PC24')):
                    continue

                # 获取被调用者（重定位目标符号）
                try:
                    callee_name = reloc['r_info_sym_name']
                except (KeyError, TypeError):
                    try:
                        callee_name = reloc.entry.r_info_sym.name
                    except Exception:
                        callee_name = None
                if not callee_name:
                    continue

                # 获取调用者：重定位所在节区的符号
                sec_name = sec.name
                # .rel.text.CALL_FUNC 模式
                if sec_name.startswith('.rel'):
                    target_sec_name = sec_name[len('.rel'):].split('+')[0]
                else:
                    continue

                caller_syms = []
                for sym in self._symtab.iter_symbols():
                    try:
                        sym_sec = self._elffile.get_section(sym['st_shndx'])
                        if sym_sec and sym_sec.name == target_sec_name:
                            caller_syms.append(sym.name)
                    except Exception:
                        pass

                callee_addr = 0
                try:
                    cs = self.get_symbol(callee_name)
                    if cs:
                        callee_addr = cs['st_value'] & ~1
                except Exception:
                    pass

                for caller in caller_syms:
                    caller_addr = 0
                    cs = self.get_symbol(caller)
                    if cs:
                        caller_addr = cs['st_value'] & ~1
                    caller_map[callee_addr if callee_addr else callee_name].add(caller)
                    callee_map[caller_addr if caller_addr else caller].add(callee_name)

        # 链接后的 .axf 通常没有 CALL 重定位（调用已在链接期解析），
        # 用 BL/BLX 反汇编补齐调用边；两种来源的重复由 set 去重。
        if self._symtab:
            self._build_addr_to_name_map()
            for sym in self._symtab.iter_symbols():
                if sym['st_info']['type'] != 'STT_FUNC' or sym['st_size'] <= 0:
                    continue
                caller_addr = sym['st_value'] & ~1
                data = self._read_bytes(caller_addr, sym['st_size'])
                if not data:
                    continue
                for callee_addr, callee_name in self._decode_bl_instructions(data, caller_addr):
                    if not callee_name:
                        continue
                    callee_map[caller_addr].add(callee_name)
                    caller_map[callee_addr].add(sym.name)

        # 构建输出
        lines = [
            f"\n调用图: {func_name}",
            "=" * 60,
            "",
            "[注意] 仅基于 ELF 重定位表中的静态直接调用，不含函数指针/间接调用。",
            "",
        ]

        # 调用者树
        lines.append(f" 调用 {func_name} 的函数 (调用者):")
        lines.append("-" * 40)
        target_key = target_addr if target_addr in caller_map else func_name
        if target_key in caller_map:
            for caller in sorted(caller_map[target_key]):
                lines.append(f"    {caller}")
        else:
            lines.append("    (未找到直接调用者)")

        lines.append("")

        # 被调用树 (depth-limited DFS)
        lines.append(f" {func_name} 调用的函数 (被调用者, depth={depth}):")
        lines.append("-" * 40)
        callee_key = target_addr if target_addr in callee_map else func_name
        visited_bfs = set()
        self._print_callee_tree(callee_key, callee_map, addr_to_name, depth, 0, visited_bfs, lines, func_name)

        return '\n'.join(lines)

    def _print_callee_tree(self, func_key, callee_map, addr_to_name, max_depth: int, current_depth: int,
                           visited: set, lines: list, root_name: str):
        """递归打印被调用树"""
        if current_depth >= max_depth:
            return

        if func_key not in callee_map:
            if current_depth == 0:
                # 根节点无被调用者
                pass
            return

        indent = "    " * current_depth
        for callee in sorted(callee_map[func_key]):
            # 避免循环引用
            edge = f"{func_key}->{callee}"
            if edge in visited:
                lines.append(f"{indent}  {callee} (循环)")
                continue
            visited.add(edge)

            lines.append(f"{indent}  {callee}")
            # 递归展开
            callee_sym = self.get_symbol(callee)
            if callee_sym:
                callee_addr = callee_sym['st_value'] & ~1
                callee_key = callee_addr if callee_addr in callee_map else callee
            else:
                callee_key = callee
            self._print_callee_tree(callee_key, callee_map, addr_to_name, max_depth, current_depth + 1, visited, lines, root_name)

    # ============================================================
    # --build-info (阶段7)
    # ============================================================

    def get_build_info(self) -> dict:
        """获取编译环境信息"""
        info = {
            'architecture': '<unknown>',
            'cpu': '<unknown>',
            'fpu': '<unknown>',
            'alignment': '<unknown>',
            'compiler': '<unknown>',
            'optimization': '<unknown>',
        }

        # 1. ELF header 基础信息
        header = self._elffile.header
        e_machine = header['e_machine']
        machine_map = {
            'EM_ARM': 'ARM',
            'EM_386': 'x86',
            'EM_X86_64': 'x86_64',
            'EM_AARCH64': 'AArch64',
        }
        info['architecture'] = machine_map.get(e_machine, e_machine)

        # 2. .ARM.attributes 解析
        arm_attr_sec = self.get_section('.ARM.attributes')
        if arm_attr_sec:
            try:
                attr_data = arm_attr_sec.data()
                self._parse_arm_attributes(attr_data, info)
            except Exception:
                pass

        # 3. .comment 节
        comment_sec = self.get_section('.comment')
        if comment_sec:
            try:
                comment_data = comment_sec.data()
                comment_str = comment_data.decode('utf-8', errors='replace').strip('\x00').strip()
                info['compiler'] = comment_str
            except Exception:
                pass

        # 4. 尝试从 DWARF 获取更多信息
        if self._has_debug_info:
            try:
                for cu in self._dwarf_info.iter_CUs():
                    top_die = cu.get_top_DIE()
                    producer = top_die.attributes.get('DW_AT_producer')
                    if producer:
                        producer_val = producer.value.decode('utf-8', errors='replace') if isinstance(producer.value, bytes) else str(producer.value)
                        info['compiler'] = producer_val
                    break
            except Exception:
                pass

        return info

    def _parse_arm_attributes(self, data: bytes, info: dict):
        """解析 ARM 属性节"""
        # ARM attributes 格式: 版本号 + 子节列表
        try:
            pos = 0
            if len(data) < 1:
                return
            version = data[pos]
            pos += 1

            while pos < len(data):
                if pos + 4 > len(data):
                    break

                section_len = struct.unpack_from('<I', data, pos)[0]
                pos += 4
                if section_len == 0:
                    break

                end_pos = pos + section_len - 4
                if end_pos > len(data):
                    break

                section_type = data[pos:pos + 1].decode('ascii', errors='replace')
                pos += 1
                sub_pos = pos

                while sub_pos < end_pos:
                    tag = data[sub_pos]
                    sub_pos += 1

                    if tag in (2, 3, 4, 5, 6, 7, 8):
                        # 带参数的无符号整数
                        if sub_pos >= end_pos:
                            break
                        val = struct.unpack_from('<I', data, sub_pos)[0] if sub_pos + 4 <= end_pos else 0
                        sub_pos += 4
                    elif tag in (32, 33, 34, 35, 36, 37):
                        # 无参标签
                        val = tag
                    elif tag in (1,):
                        if sub_pos >= end_pos:
                            break
                        str_len = data[sub_pos]
                        sub_pos += 1
                        val = data[sub_pos:sub_pos + str_len].decode('ascii', errors='replace')
                        sub_pos += str_len
                    else:
                        # 跳过未知
                        break

                    # 映射常见 ARM 属性
                    self._map_arm_attr(tag, val, info)

                pos = end_pos
        except Exception:
            pass

    def _map_arm_attr(self, tag: int, val, info: dict):
        """映射 ARM 属性标签到可读信息"""
        cpu_map = {
            0: 'Pre-v4', 1: 'ARM v4', 2: 'ARM v4T', 3: 'ARM v5T',
            4: 'ARM v5TE', 5: 'ARM v5TEJ', 6: 'ARM v6', 7: 'ARM v6KZ',
            8: 'ARM v6T2', 9: 'ARM v6K', 10: 'ARM v7', 11: 'ARM v6-M',
            12: 'ARM v6S-M', 13: 'ARM v7E-M', 14: 'ARM v8-A',
            15: 'ARM v8-R', 16: 'ARM v8-M Baseline', 17: 'ARM v8-M Mainline',
            18: 'ARM v8.1-M Mainline', 19: 'ARM v9-A',
        }
        fpu_map = {
            0: 'VFPv1', 1: 'VFPv2', 2: 'VFPv3', 3: 'VFPv3_FP16',
            4: 'VFPv4', 5: 'VFPv4_D16', 6: 'FPv5',
            7: 'VFPv4_SP_D16', 8: 'FPv5_SP_D16',
        }

        # Tag 6 = CPU_arch, Tag 10 = FP_arch
        try:
            if isinstance(val, int):
                if tag in (6,):
                    info['cpu'] = cpu_map.get(val, f'ARM arch {val}')
                elif tag in (10,):
                    info['fpu'] = fpu_map.get(val, f'FP arch {val}')
                elif tag in (36,):  # Tag_ABI_FP_number_model
                    info['fpu'] = 'Hard FP' if val == 1 else 'Soft FP'
                elif tag in (34,):  # Tag_ABI_align8_needed
                    info['alignment'] = '64-bit' if val == 1 else '32-bit (default)'
        except Exception:
            pass

    # ============================================================
    # --checksum (阶段8)
    # ============================================================

    def get_checksum(self, sections: list[str] = None) -> dict[str, str]:
        """对指定段计算 SHA256 哈希"""
        if sections is None:
            # 默认: .text, .rodata, .data
            sections = []
            for name in ['.text', '.rodata', '.data']:
                if name in self._section_names:
                    sections.append(name)
            # 如果以上都不存在，使用所有 alloc 段
            if not sections:
                for sec in self._elffile.iter_sections():
                    if sec.header.sh_flags & 2:  # SHF_ALLOC
                        sections.append(sec.name)

        results = {}
        for sec_name in sections:
            sec = self.get_section(sec_name)
            if sec:
                sha = hashlib.sha256(sec.data()).hexdigest()
                results[sec_name] = sha
            else:
                results[sec_name] = '<段不存在>'

        return results


# ============================================================
# CLI
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='axf_inspector.py',
        description='AxFInspector — 基于 pyelftools 的 ELF/DWARF 符号级分析器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
子命令示例:
  %(prog)s --axf firmware.axf --addr2line 0x08001234
  %(prog)s --axf firmware.axf --disasm main --mixed
  %(prog)s --axf firmware.axf --stackframe logprintf
  %(prog)s --axf firmware.axf --top --type func --limit 10
  %(prog)s --axf firmware.axf --struct GPIO_InitTypeDef --expand
  %(prog)s --axf firmware.axf --callgraph MX_FMC_Init --depth 3
  %(prog)s --axf firmware.axf --segments
  %(prog)s --axf firmware.axf --build-info
  %(prog)s --axf firmware.axf --symbol-addr hsdram1
  %(prog)s --axf firmware.axf --checksum --section .text,.rodata
        """,
    )

    parser.add_argument(
        '--axf', '-f',
        required=True,
        help='.axf / ELF 固件文件路径',
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='以 JSON 格式输出（人类可读为默认格式）',
    )

    # P0 子命令
    parser.add_argument(
        '--addr2line',
        metavar='ADDR',
        help='地址转源码位置（十六进制，如 0x08001234）',
    )

    parser.add_argument(
        '--callstack',
        metavar='ADDR',
        help='--addr2line 的别名，强调内联调用链展开',
    )

    parser.add_argument(
        '--disasm',
        metavar='FUNC',
        help='反汇编指定函数',
    )

    parser.add_argument(
        '--stackframe',
        metavar='FUNC',
        help='分析函数栈帧大小（解码 Thumb 前言中的 PUSH + SUB SP）',
    )

    parser.add_argument(
        '--stackdepth',
        metavar='FUNC',
        help='递归分析调用链最大栈深度（BL 指令追踪 + 栈帧累加）',
    )

    parser.add_argument(
        '--indirect-penalty',
        metavar='N',
        type=int,
        default=80,
        help='(配合 --stackdepth) 含间接调用的每层启发式预算字节数 (默认80，不是上界)',
    )

    parser.add_argument('--audit-tasks', metavar='MANIFEST',
                        help='Audit task allocations and callback paths from a JSON manifest')
    parser.add_argument('--project-root', default='.',
                        help='Root for allocation source paths in the audit manifest')

    parser.add_argument(
        '--context-bytes',
        '--freertos-context',
        dest='context_bytes',
        metavar='N',
        type=int,
        default=0,
        help='(与 --stackdepth 配合) 额外上下文字节预算：异常帧、内核/运行时保存的寄存器等；'
             '默认 0 表示未计入，不自动推断。--freertos-context 为兼容旧调用的别名。',
    )

    parser.add_argument(
        '--safety-factor',
        metavar='F',
        type=float,
        default=1.5,
        help='(配合 --stackdepth) 安全系数 (默认 1.5)',
    )

    parser.add_argument(
        '--mixed',
        action='store_true',
        help='(配合 --disasm) 混合显示源码行',
    )

    parser.add_argument(
        '--top',
        action='store_true',
        help='显示最大符号排行榜（按大小降序）',
    )

    parser.add_argument(
        '--type',
        metavar='TYPE',
        choices=['func', 'data'],
        help='(配合 --top) 过滤符号类型',
    )

    parser.add_argument(
        '--limit',
        metavar='N',
        type=int,
        default=20,
        help='(配合 --top / --unused) 显示数量限制 (默认 20)',
    )

    parser.add_argument(
        '--region',
        metavar='REGION',
        choices=['all', 'ram', 'flash'],
        default='all',
        help='(配合 --top) 按区域过滤：ram=可写数据段(.data/.bss)，'
             'flash=只读代码/常量(.text/.rodata)，all=全部 (默认 all)',
    )

    parser.add_argument(
        '--unused',
        action='store_true',
        help='列出“已定义但看起来未被引用”的**静态数据对象**候选（死静态，best-effort）',
    )

    parser.add_argument(
        '--include-funcs',
        action='store_true',
        help='(配合 --unused) 同时列出函数候选（函数指针派发不可见，误报率高，慎用）',
    )

    parser.add_argument(
        '--min-size',
        metavar='N',
        type=int,
        default=0,
        help='(配合 --unused) 只列出不小于 N 字节的符号',
    )

    parser.add_argument(
        '--struct',
        metavar='NAME',
        help='显示结构体/联合体成员布局',
    )

    parser.add_argument(
        '--expand',
        action='store_true',
        help='(配合 --struct) 递归展开嵌套结构体',
    )

    parser.add_argument(
        '--callgraph',
        metavar='FUNC',
        help='显示函数静态调用图',
    )

    parser.add_argument(
        '--depth',
        metavar='N',
        type=int,
        default=2,
        help='(配合 --callgraph) 递归深度 (默认 2)',
    )

    parser.add_argument(
        '--segments',
        action='store_true',
        help='显示程序头/段内存映射',
    )

    # P1 子命令
    parser.add_argument(
        '--build-info',
        action='store_true',
        help='显示编译环境与 ABI 属性',
    )

    parser.add_argument(
        '--symbol-addr',
        metavar='NAME',
        help='查询符号的绝对虚拟地址',
    )

    parser.add_argument(
        '--checksum',
        action='store_true',
        help='计算指定段的 SHA256 哈希',
    )

    parser.add_argument(
        '--section',
        metavar='SECTIONS',
        help='(配合 --checksum) 指定段，逗号分隔 (默认 .text,.rodata,.data)',
    )

    parser.add_argument(
        '--version',
        action='version',
        version='AxFInspector v1.0.0',
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.audit_tasks:
        try:
            manifest = json.loads(Path(args.audit_tasks).read_text(encoding='utf-8-sig'))
            analyzer = ELFAnalyzer(args.axf)
            report = analyzer.audit_tasks(manifest, Path(args.project_root))
        except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
            parser.error(f'task audit failed: {error}')
        print(json.dumps(report, ensure_ascii=True, indent=2) if args.json
              else analyzer.format_task_audit(report))
        return

    # 基本依赖检测
    if not _pyelftools_available:
        sys.exit(
            "错误: 缺少 pyelftools 库。请安装:\n"
            "  pip install pyelftools>=0.29"
        )

    # 检查 --axf 参数
    if not args.axf:
        sys.exit("错误: 必须指定 --axf <固件文件路径>")

    try:
        analyzer = ELFAnalyzer(args.axf)
    except Exception as e:
        sys.exit(f"错误: 无法打开 ELF 文件 '{args.axf}': {e}")

    import json as json_mod

    # ---- 子命令分发 ----

    # --addr2line / --callstack
    addr = args.addr2line or args.callstack
    if addr:
        try:
            int_addr = int(addr, 16)
        except ValueError:
            sys.exit(f"错误: 无效的地址 '{addr}'，请使用十六进制格式 (如 0x08001234)")

        frames = analyzer.addr2line(int_addr)
        if not frames:
            print(f"{addr}: <无调试信息，无法定位源码位置>")
            sys.exit(1)

        if args.json:
            json_frames = [{'file': f.file, 'line': f.line, 'column': f.column, 'function': f.function} for f in frames]
            print(json_mod.dumps(json_frames, ensure_ascii=False, indent=2))
        else:
            for i, frame in enumerate(frames):
                if i == 0:
                    print(f"\n{addr}: {frame}")
                else:
                    indent = '  ' + '  ' * (i - 1) + '└─ 内联自: '
                    print(f"{indent}{frame}")
        return

    # --disasm
    if args.disasm:
        result = analyzer.disassemble_function(args.disasm, mixed=args.mixed)
        print(result)
        return

    # --stackframe
    if args.stackframe:
        info = analyzer.analyze_stackframe(args.stackframe)
        if info is None:
            print(f"未找到函数: '{args.stackframe}'，或该符号不是函数")
            sys.exit(1)
        if args.json:
            print(json_mod.dumps({
                'name': info.name,
                'address': f'0x{info.address:08X}',
                'code_size': info.code_size,
                'is_thumb': info.is_thumb,
                'push_bytes': info.push_bytes,
                'push_regs': info.push_regs,
                'sub_sp_total': info.sub_sp_total,
                'stack_frame': info.stack_frame,
                'source': info.source,
                'prologue_ops': info.prologue_ops,
            }, ensure_ascii=False, indent=2))
        else:
            print(f"\n函数栈帧分析: {args.stackframe}")
            print("-" * 50)
            print(f"  地址:       0x{info.address:08X} ({'Thumb' if info.is_thumb else 'ARM'})")
            print(f"  代码大小:   {info.code_size} bytes")
            print(f"  数据来源:   {info.source}")
            print(f"  前言机器码: {info.raw_bytes_hex}")
            print("  分析信息:")
            for op in info.prologue_ops:
                print(f"    {op}")
            if info.source == "prologue":
                print(f"  PUSH 寄存器: {len(info.push_regs)} ({info.push_bytes}B)")
                print(f"  局部变量:   {info.sub_sp_total}B (SUB SP)")
            print(f"  总栈帧:     {info.stack_frame}B")
        return

    # --stackdepth
    if args.stackdepth:
        sdc = StackDepthConfig(
            indirect_penalty=args.indirect_penalty,
            context_bytes=args.context_bytes,
            safety_factor=args.safety_factor,
        )
        root = analyzer.analyze_stack_depth(args.stackdepth, config=sdc)
        if root is None:
            print(f"未找到函数: '{args.stackdepth}'，或该符号不是函数")
            sys.exit(1)
        print(analyzer.format_stack_depth_tree(root, config=sdc))
        return

    # --unused
    if getattr(args, 'unused', False):
        syms = analyzer.get_unused_symbols(min_size=args.min_size,
                                           include_funcs=args.include_funcs)
        shown = syms[:args.limit]
        kind = "静态数据对象" if not args.include_funcs else "静态数据对象 + 函数"
        if args.json:
            print(json_mod.dumps([
                {'rank': i+1, 'name': s.name, 'size': s.size, 'type': s.st_type,
                 'region': s.region, 'address': hex(s.address)}
                for i, s in enumerate(shown)
            ], ensure_ascii=False, indent=2))
        else:
            print(f"\n疑似未引用的{kind}（best-effort，共 {len(syms)} 个，"
                  f"显示前 {len(shown)} 个）:")
            print("-" * 88)
            print(f"{'#':<5} {'名称':<40} {'大小(B)':<12} {'类型':<8} {'区域':<7} {'地址'}")
            print("-" * 88)
            for i, s in enumerate(shown):
                print(f"{i+1:<5} {s.name:<40} {s.size:<12,} {s.st_type:<8} "
                      f"{s.region:<7} 0x{s.address:08X}")
            print("-" * 88)
            print("说明：判定基于“指针字扫描 + BL/BLX + movw/movt 地址装载”，"
                  "可能把仅在调试信息、链接脚本或未识别间接跳转中被引用的符号误列为候选；")
            print("     删除前请用 --callgraph / --disasm 复核；函数级判定默认关闭"
                  "（--include-funcs 可开启，误报率高）。\n")
        return

    # --top
    if args.top:
        symbols = analyzer.get_symbols_sorted_by_size(st_type=args.type,
                                                      region=args.region)
        total_size = sum(s.size for s in symbols)
        symbols = symbols[:args.limit]

        if args.json:
            json_symbols = [{'rank': i+1, 'name': s.name, 'size': s.size,
                             'type': s.st_type, 'section': s.section,
                             'region': s.region}
                            for i, s in enumerate(symbols)]
            print(json_mod.dumps(json_symbols, ensure_ascii=False, indent=2))
        else:
            region_label = (args.region or 'all').upper()
            print(f"\n最大符号排行榜 (region={region_label}, "
                  f"共 {len(symbols)} 个, 限制 {args.limit}, 合计 {total_size:,} B):")
            print("-" * 88)
            print(f"{'#':<5} {'名称':<40} {'大小(B)':<12} {'类型':<8} {'区域':<7} {'段':<15}")
            print("-" * 88)
            for i, s in enumerate(symbols):
                size_str = f"{s.size:,}"
                print(f"{i+1:<5} {s.name:<40} {size_str:<12} {s.st_type:<8} "
                      f"{s.region:<7} {s.section:<15}")
            print("-" * 88)
            print(f"合计: {total_size:,} B")
        return

    # --struct
    if args.struct:
        members = analyzer.get_struct_layout(args.struct, expand=args.expand)
        total_size = analyzer.get_struct_byte_size(args.struct)
        if not members and total_size == 0:
            print(f"未找到结构体/联合体: '{args.struct}'")
            sys.exit(1)

        if args.json:
            json_members = []
            for m in members:
                d = {'name': m.name, 'type': m.type_name, 'offset': m.offset, 'size': m.size}
                if m.bit_size > 0:
                    d['bit_offset'] = m.bit_offset
                    d['bit_size'] = m.bit_size
                if m.children:
                    d['children'] = [{'name': c.name, 'type': c.type_name, 'offset': c.offset, 'size': c.size} for c in m.children]
                json_members.append(d)
            print(json_mod.dumps({'name': args.struct, 'size': total_size,
                                  'members': json_members},
                                 ensure_ascii=False, indent=2))
        else:
            print(f"\n结构体布局: {args.struct}  (总大小: {total_size} B)")
            print("-" * 80)
            print(f"{'偏移(B)':<9} {'类型':<30} {'成员':<20} {'备注'}")
            print("-" * 80)
            for m in members:
                print(m)
                for child in m.children:
                    print(f"  {child}")
        return

    # --callgraph
    if args.callgraph:
        result = analyzer.get_callgraph(args.callgraph, depth=args.depth)
        print(result)
        return

    # --segments
    if args.segments:
        segments = analyzer.get_segments()

        if args.json:
            json_segs = [{'type': s.seg_type, 'vaddr': f'0x{s.vaddr:08X}', 'paddr': f'0x{s.paddr:08X}',
                         'file_size': s.file_size, 'mem_size': s.mem_size, 'flags': s.flags} for s in segments]
            print(json_mod.dumps(json_segs, ensure_ascii=False, indent=2))
        else:
            print(f"\n程序头/段信息 ({len(segments)} 个段):")
            print("-" * 85)
            print(f"{'类型':<12} {'虚拟地址':<14} {'物理地址':<14} {'文件大小':<10} {'内存大小':<10} {'权限'}")
            print("-" * 85)
            for s in segments:
                fs = f"{s.file_size:#x}" if s.file_size else '0'
                ms = f"{s.mem_size:#x}" if s.mem_size else '0'
                print(f"{s.seg_type:<12} 0x{s.vaddr:012X} 0x{s.paddr:012X} {s.file_size:<10} {s.mem_size:<10} {s.flags}")
        return

    # --build-info
    if args.build_info:
        info = analyzer.get_build_info()

        if args.json:
            print(json_mod.dumps(info, ensure_ascii=False, indent=2))
        else:
            print(f"\n编译环境信息:")
            print("-" * 50)
            print(f"  架构:       {info['architecture']}")
            print(f"  CPU:        {info['cpu']}")
            print(f"  FPU:        {info['fpu']}")
            print(f"  对齐:       {info['alignment']}")
            print(f"  编译器:     {info['compiler']}")
            print(f"  优化级别:   {info['optimization']}")
        return

    # --symbol-addr
    if args.symbol_addr:
        sym_info = analyzer.get_symbol_addr(args.symbol_addr)
        if not sym_info:
            print(f"未找到符号: '{args.symbol_addr}'")
            sys.exit(1)

        if args.json:
            print(json_mod.dumps({'name': sym_info.name, 'address': f'0x{sym_info.address:08X}',
                                  'size': sym_info.size, 'type': sym_info.st_type, 'section': sym_info.section},
                                 ensure_ascii=False, indent=2))
        else:
            print(f"\n符号: {sym_info.name}")
            print(f"  虚拟地址: 0x{sym_info.address:08X}")
            print(f"  大小:     {sym_info.size} 字节")
            print(f"  类型:     {sym_info.st_type}")
            print(f"  所在段:   {sym_info.section}")
        return

    # --checksum
    if args.checksum:
        sec_names = None
        if args.section:
            sec_names = [s.strip() for s in args.section.split(',')]
        checksums = analyzer.get_checksum(sections=sec_names)

        if args.json:
            print(json_mod.dumps(checksums, ensure_ascii=False, indent=2))
        else:
            print(f"\n段校验和 (SHA256):")
            print("-" * 76)
            for sec, sha in checksums.items():
                print(f"  {sec:<20} {sha}")
        return

    # 无子命令
    parser.print_help()


if __name__ == '__main__':
    main()
