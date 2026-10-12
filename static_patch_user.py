#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

shaderapidx9.dll Patcher (Fixes "Too Many Indices Error")

背景
----
L4D2Fix（kpatch.dll）原本的做法是运行时注入，在游戏进程里把
"Too Many Indices" 相关的立即数 0x8000 (VERTEX_BUFFER_SIZE = 32768) 改掉，
见 src/hooks_indices.h::PatchIndices()。因为改的是内存，进 VAC 服有风险。

本脚本把那 5 处立即数**直接写进磁盘上的 DLL 文件**，于是：
  * 不需要注入 kpatch.dll，进程内存里没有额外的补丁代码；
  * 不改动文件大小、不改动节表布局，只替换 .text 里 5 个 32 位立即数；
  * 换来的代价：文件与 Steam 仓库不一致，"验证游戏文件完整性" 会还原它。

本脚本不（也不能）注入 L4D2Fix 使用的 DynamicVB / GetMaxToRender 这两个运行时 hook
（它们需要在游戏运行时改代码/改参数），只对应 cfg::Indices 的修正。

安全约定（重要）
----------------
1. 目标文件已经是补丁状态时，只报告、不写入（退出码 2），不会静默覆盖。
2. 只改写“当前立即数 == 0x8000”或“== 配置值”的站点；出现别的数值时
   默认拒绝写入并报告（退出码 3），需要 --force 才覆盖。
3. 原地修改前默认生成备份 <dll>.bak（绝不覆盖已存在的备份）。
4. 写入用“同目录临时文件 + 原子替换”，并在写完后重新读盘校验。

用法
----
    python tools/static_patch.py "<游戏目录>\\bin\\shaderapidx9.dll" --check
    python tools/static_patch.py "<游戏目录>\\bin\\shaderapidx9.dll"
    python tools/static_patch.py ...dll --restore

退出码
------
    0  已写入补丁（--check 时表示“可以打补丁”）
    1  用法 / 文件 / PE 结构错误
    2  目标已是补丁状态，未做任何修改
    3  有站点状态异常（需要 --force 或人工确认），未完成
    4  找不到补丁点位（不支持的版本，或不是目标 DLL）
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import os
import struct
import sys
from typing import Optional

TOOL_NAME = "l4d2fix-static-patch"
TOOL_VERSION = "1.0.0"

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_ALREADY = 2
EXIT_INCOMPLETE = 3
EXIT_NOT_FOUND = 4

# src/hooks_indices.h 里被替换掉的那个立即数
ORIGINAL_VALUE = 0x8000
# kpatch.ini [Indices] value 的默认值
DEFAULT_VALUE = 131072

# 标记：借用节表里一个空闲的表项（40 字节），不影响加载器（它只看 NumberOfSections）
MARKER_NAME = b"L4D2SPT"
MARKER_VERSION = 1
MAX_SECTIONS = 96
SECTION_ENTRY_SIZE = 40
HEADER_REGION_LABEL = "<headers>"
MACHINE_I386 = 0x014C
IMAGE_DIRECTORY_ENTRY_SECURITY = 4


class PatchError(Exception):
    """用法/文件/PE 结构层面的错误 -> 退出码 1"""


# --------------------------------------------------------------------------
# 模式表：与 src/hooks_indices.h::PatchIndices() 一一对应
#
# 坑：kpatch.dll 用的是「上一个匹配处的地址」作为下一次搜索的起点，
#     而且第 5 个站点（Unknown）是从第 3 个站点（CreateVertexIDBuffer）
#     开始搜的，不是从第 4 个。这里必须照样复刻，顺序错了就会打到别的地方。
#
# 立即数位置写成 ?? 通配，这样同一个模式既能认出没打补丁的文件（值 0x8000），
# 也能认出已经打过补丁的文件（值 = 配置值，或别的数值）。
# --------------------------------------------------------------------------
PATTERN_A = "68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 04"
PATTERN_B = "68 ?? ?? ?? ?? 50 8B"
PATTERN_C = "0F B6 C0 50 68 ?? ?? ?? ?? 53 8B CF E8 ?? ?? ?? ??"


@dataclasses.dataclass(frozen=True)
class Site:
    index: int
    name: str          # hooks_indices.h 里的 tag
    pattern: str       # 通配立即数的模式
    write_offset: int  # 立即数相对匹配起点的偏移（= hooks_indices.h 的 w_offset）
    search_from: Optional[int]  # 从哪个站点的匹配处开始搜索；None = 从镜像开头
    desc: str


SITES = (
    Site(0, "CreateEmptyColorMesh", PATTERN_A, 6, None,
         "push 0x8000（CreateEmptyColorMesh 的顶点上限）"),
    Site(1, "CreateEmptyColorMesh Later", PATTERN_B, 1, 0,
         "同一函数后段的 push 0x8000"),
    Site(2, "CreateVertexIDBuffer", PATTERN_A, 6, 1,
         "push 0x8000（CreateVertexIDBuffer 的顶点上限）"),
    Site(3, "CreateVertexIDBuffer Later", PATTERN_B, 1, 2,
         "同一函数后段的 push 0x8000"),
    Site(4, "Unknown", PATTERN_C, 5, 2,
         "0F B6 C0 50 68 0x8000 ... （kpatch.dll 里名为 Unknown 的站点）"),
)


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def parse_pattern(text: str) -> list[Optional[int]]:
    """'68 ?? ?? 50' -> [0x68, None, None, 0x50]"""
    out: list[Optional[int]] = []
    for token in text.split():
        if token in ("?", "??"):
            out.append(None)
        else:
            try:
                value = int(token, 16)
            except ValueError as exc:
                raise PatchError(f"模式串里有非法字节 {token!r}: {text}") from exc
            if not 0 <= value <= 0xFF or len(token) > 2:
                raise PatchError(f"模式串里有非法字节 {token!r}: {text}")
            out.append(value)
    if not out:
        raise PatchError(f"空模式串: {text!r}")
    return out


def render_pattern(pattern: list[Optional[int]], pin: Optional[tuple[int, int]] = None) -> str:
    """把模式渲染回字符串；pin=(偏移, 值) 时把立即数写成具体字节，便于人眼比对。"""
    items: list[str] = []
    for i, b in enumerate(pattern):
        if pin and pin[0] <= i < pin[0] + 4:
            b = (pin[1] >> (8 * (i - pin[0]))) & 0xFF
        items.append("??" if b is None else f"{b:02X}")
    return " ".join(items)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hexval(value: int, width: int = 8) -> str:
    return f"0x{value:0{width}X}"


def parse_int(text: str) -> int:
    text = text.strip()
    try:
        return int(text, 0)
    except ValueError as exc:
        raise PatchError(f"无法解析数值 {text!r}（十进制或 0x 十六进制）") from exc


def compute_pe_checksum(data: bytes, checksum_off: int) -> int:
    """微软 imagehlp CheckSumMappedFile 的等价实现（校验和字段本身按 0 处理）。"""
    total = 0
    size = len(data)
    i = 0
    while i + 1 < size:
        if i == checksum_off:
            i += 4
            continue
        total += data[i] | (data[i + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
        i += 2
    if i < size:
        total += data[i]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    total += size
    return total & 0xFFFFFFFF


# --------------------------------------------------------------------------
# PE 解析 / 按 RVA 顺序的字节流
# --------------------------------------------------------------------------
@dataclasses.dataclass
class Section:
    index: int
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_ptr: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)


@dataclasses.dataclass
class Region:
    rva: int
    file_off: int
    length: int
    label: str


@dataclasses.dataclass
class Match:
    rva: int
    file_off: int
    region_label: str


@dataclasses.dataclass
class Marker:
    version: int
    value: int
    offsets: list[int]
    slot_off: int


class PEFile:
    """只读的 PE 视图：把文件按“镜像里的 RVA 顺序”摊平成可搜索的区间。

    kpatch.dll 扫的是已加载的镜像（RVA 递增），所以这里也按 VirtualAddress
    排序、跳过文件里没有对应原始数据的区间，保证匹配顺序和运行时一致。
    """

    def __init__(self, data: bytes, label: str = "<memory>"):
        self.label = label
        self.data = bytearray(data)
        self.size = len(self.data)
        self._parse()

    # -- 解析 ---------------------------------------------------------------
    def _u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def _parse(self) -> None:
        if self.size < 0x40 or self.data[0:2] != b"MZ":
            raise PatchError(f"{self.label}: 不是有效的 PE 文件（缺少 MZ 头）")
        self.e_lfanew = self._u32(0x3C)
        if self.e_lfanew + 24 > self.size:
            raise PatchError(f"{self.label}: e_lfanew 越界，文件已损坏")
        if bytes(self.data[self.e_lfanew:self.e_lfanew + 4]) != b"PE\0\0":
            raise PatchError(f"{self.label}: 缺少 PE 签名")

        coff = self.e_lfanew + 4
        (self.machine, self.num_sections, self.timestamp, _sym_ptr, _num_sym,
         self.opt_header_size, self.characteristics) = struct.unpack_from("<HHIIIHH", self.data, coff)

        self.opt = coff + 20
        if self.opt + self.opt_header_size > self.size or self.opt_header_size < 0x60:
            raise PatchError(f"{self.label}: 可选头大小异常（{self.opt_header_size}）")

        magic = self._u16(self.opt)
        if magic == 0x20B:
            raise PatchError(
                f"{self.label}: 这是 64 位 (PE32+) 文件；L4D2 的 shaderapidx9.dll 应该是 32 位")
        if magic != 0x10B:
            raise PatchError(f"{self.label}: 未知的可选头 magic {hexval(magic, 4)}")
        if self.machine != MACHINE_I386:
            raise PatchError(
                f"{self.label}: 机器类型 {hexval(self.machine, 4)} 不是 i386(0x014C)；"
                "模式表只针对 32 位版本")

        self.image_base = self._u32(self.opt + 28)
        self.size_of_image = self._u32(self.opt + 56)
        self.size_of_headers = self._u32(self.opt + 60)
        self.checksum = self._u32(self.opt + 64)
        self.checksum_off = self.opt + 64
        num_rva = self._u32(self.opt + 92)
        data_dir = self.opt + 96

        self.security_dir = (0, 0)
        if num_rva > IMAGE_DIRECTORY_ENTRY_SECURITY and data_dir + 8 * (IMAGE_DIRECTORY_ENTRY_SECURITY + 1) <= self.opt + self.opt_header_size:
            self.security_dir = (self._u32(data_dir + 8 * IMAGE_DIRECTORY_ENTRY_SECURITY),
                                 self._u32(data_dir + 8 * IMAGE_DIRECTORY_ENTRY_SECURITY + 4))

        if not 1 <= self.num_sections <= MAX_SECTIONS:
            raise PatchError(f"{self.label}: 节数量异常（{self.num_sections}）")
        self.section_table_off = self.opt + self.opt_header_size
        if self.section_table_off + self.num_sections * SECTION_ENTRY_SIZE > self.size:
            raise PatchError(f"{self.label}: 节表越界，文件已损坏")

        self.sections: list[Section] = []
        for i in range(self.num_sections):
            off = self.section_table_off + i * SECTION_ENTRY_SIZE
            raw_name = bytes(self.data[off:off + 8])
            name = raw_name.rstrip(b"\0").decode("latin-1") or f"<{i}>"
            (vsize, vaddr, rawsize, rawptr, _reloc, _lineno,
             _nreloc, _nlineno, chars) = struct.unpack_from("<IIIIIIHHI", self.data, off + 8)
            self.sections.append(Section(i, name, vsize, vaddr, rawsize, rawptr, chars))

        self.regions = self._build_regions()

    def _build_regions(self) -> list[Region]:
        regions: list[Region] = []
        header_len = min(self.size_of_headers, self.size)
        if header_len > 0:
            regions.append(Region(0, 0, header_len, HEADER_REGION_LABEL))
        for sec in self.sections:
            if sec.raw_ptr == 0 or sec.raw_size == 0 or sec.raw_ptr >= self.size:
                continue  # 纯虚拟节（内存里全是 0），模式不可能匹配
            length = min(sec.raw_size, self.size - sec.raw_ptr)
            regions.append(Region(sec.virtual_address, sec.raw_ptr, length, sec.name))
        regions.sort(key=lambda r: r.rva)

        # 裁剪 RVA 重叠，避免把 header 区或前一个节重复扫一遍
        out: list[Region] = []
        prev_end = 0
        for reg in regions:
            start = max(reg.rva, prev_end)
            cut = start - reg.rva
            if cut >= reg.length:
                continue
            out.append(Region(start, reg.file_off + cut, reg.length - cut, reg.label))
            prev_end = start + reg.length - cut
        return out

    # -- 查询 ---------------------------------------------------------------
    def rva_of(self, file_off: int) -> Optional[int]:
        for reg in self.regions:
            if reg.file_off <= file_off < reg.file_off + reg.length:
                if reg.label == HEADER_REGION_LABEL:
                    return file_off
                return reg.rva + (file_off - reg.file_off)
        for sec in self.sections:
            if sec.raw_ptr <= file_off < sec.raw_ptr + sec.raw_size:
                return sec.virtual_address + (file_off - sec.raw_ptr)
        return None

    def read_u32(self, file_off: int) -> int:
        return self._u32(file_off)

    def find(self, pattern: list[Optional[int]], start_rva: int,
             require_value: Optional[int] = None, imm_off: int = 0) -> Optional[Match]:
        """在 RVA >= start_rva 的位置找第一个匹配。

        require_value 不为 None 时，只接受 (匹配处 + imm_off) 的 4 字节小端值
        等于它的候选 —— 这就是 kpatch.dll 严格模式（立即数必须还是 0x8000）。
        """
        plen = len(pattern)
        for reg in self.regions:
            if reg.rva + reg.length <= start_rva:
                continue
            begin_rva = max(reg.rva, start_rva)
            base = reg.file_off + (begin_rva - reg.rva)
            i = base
            last = reg.file_off + reg.length - plen
            while i <= last:
                matched = True
                for j, byte in enumerate(pattern):
                    if byte is not None and self.data[i + j] != byte:
                        matched = False
                        break
                if matched and (require_value is None or self._u32(i + imm_off) == require_value):
                    return Match(begin_rva + (i - base), i, reg.label)
                i += 1
        return None

    # -- 标记（借用一个空闲节表项） -----------------------------------------
    def _slot_bounds(self) -> tuple[int, int]:
        start = self.section_table_off
        end = min(start + MAX_SECTIONS * SECTION_ENTRY_SIZE, self.size)
        return start, end

    def _marker_slots(self) -> list[int]:
        start, end = self._slot_bounds()
        slots: list[int] = []
        off = start
        while off + SECTION_ENTRY_SIZE <= end:
            # 节名固定 8 字节，短名字会被 \0 补齐
            if bytes(self.data[off:off + 8]).rstrip(b"\0") == MARKER_NAME:
                slots.append(off)
            off += SECTION_ENTRY_SIZE
        return slots

    def read_marker(self) -> Optional[Marker]:
        slots = self._marker_slots()
        if not slots:
            return None
        off = slots[0]
        version, value, count = struct.unpack_from("<III", self.data, off + 8)
        offsets = list(struct.unpack_from("<5I", self.data, off + 20)) if 0 < count <= 5 else []
        return Marker(version, value, offsets[:count], off)

    def find_free_slot(self) -> Optional[int]:
        """返回一个全零、且不会覆盖任何节数据的空闲节表项偏移；没有就返回 None。"""
        start, end = self._slot_bounds()
        if self.size_of_headers and start < self.size_of_headers:
            end = min(end, self.size_of_headers)  # 标记只能落在会被加载的头部区域里
        off = start + self.num_sections * SECTION_ENTRY_SIZE
        while off + SECTION_ENTRY_SIZE <= end:
            candidate = (off, off + SECTION_ENTRY_SIZE)
            overlaps = any(
                sec.raw_ptr < candidate[1] and candidate[0] < sec.raw_ptr + sec.raw_size
                for sec in self.sections if sec.raw_size
            )
            if not overlaps and bytes(self.data[off:off + SECTION_ENTRY_SIZE]) == b"\0" * SECTION_ENTRY_SIZE:
                return off
            off += SECTION_ENTRY_SIZE
        return None

    def write_marker(self, value: int, offsets: list[int]) -> Optional[int]:
        """写补丁标记；已有标记就原地更新，避免留下过期的旧标记。"""
        slots = self._marker_slots()
        slot = slots[0] if slots else self.find_free_slot()
        if slot is None:
            return None
        for extra in slots[1:]:
            self.data[extra:extra + SECTION_ENTRY_SIZE] = b"\0" * SECTION_ENTRY_SIZE
        offsets = offsets[:5]
        blob = struct.pack("<8sIII5I", MARKER_NAME, MARKER_VERSION, value, len(offsets),
                           *(offsets + [0] * (5 - len(offsets))))
        self.data[slot:slot + SECTION_ENTRY_SIZE] = blob
        return slot


# --------------------------------------------------------------------------
# 扫描 / 判定
# --------------------------------------------------------------------------
@dataclasses.dataclass
class SiteState:
    site: Site
    match: Optional[Match]
    current: Optional[int]
    state: str            # original | patched | other | missing

    @property
    def runtime_hits(self) -> bool:
        """kpatch.dll 的严格扫描（立即数仍为 0x8000）是否会命中这里。

        立即数被改过以后，运行时的严格模式就认不出这个点位了 —— 这正是
        “已经打过静态补丁”的表现。
        """
        return self.current == ORIGINAL_VALUE


def resolve_chain(pe: PEFile, strict: bool) -> list[Optional[Match]]:
    """按 hooks_indices.h 的顺序链式扫描。

    strict=True 完全复刻 kpatch.dll（立即数必须仍是 0x8000）；
    strict=False 用通配立即数，用来识别“已经打过补丁”的文件。
    """
    found: list[Optional[Match]] = []
    for site in SITES:
        if site.search_from is None:
            start_rva = 0
        else:
            prev = found[site.search_from]
            if prev is None:
                found.append(None)
                continue
            start_rva = prev.rva
        found.append(pe.find(parse_pattern(site.pattern), start_rva,
                             require_value=ORIGINAL_VALUE if strict else None,
                             imm_off=site.write_offset))
    return found


def analyze(pe: PEFile, value: int) -> list[SiteState]:
    chain = resolve_chain(pe, strict=False)
    states: list[SiteState] = []
    for i, site in enumerate(SITES):
        match = chain[i]
        if match is None:
            states.append(SiteState(site, None, None, "missing"))
            continue
        current = pe.read_u32(match.file_off + site.write_offset)
        if current == value:
            state = "patched"
        elif current == ORIGINAL_VALUE:
            state = "original"
        else:
            state = "other"
        states.append(SiteState(site, match, current, state))
    return states


STATE_TEXT = {
    "original": "未打补丁",
    "patched": "已是补丁值",
    "other": "数值异常",
    "missing": "未找到",
}


def decide(states: list[SiteState]) -> tuple[str, list[SiteState]]:
    """返回 (结论, 需要写入的站点列表)"""
    if any(s.state == "missing" for s in states):
        return "not_found", []
    if all(s.state == "patched" for s in states):
        return "patched", []
    if all(s.state == "original" for s in states):
        return "unpatched", list(states)
    if any(s.state == "other" for s in states):
        return "other", [s for s in states if s.state == "original"]
    return "partial", [s for s in states if s.state == "original"]


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------
class Ui:
    def __init__(self, json_mode: bool = False):
        self.json_mode = json_mode

    def say(self, text: str = "") -> None:
        if not self.json_mode:
            print(text)

    def warn(self, text: str) -> None:
        if not self.json_mode:
            print(f"[警告] {text}", file=sys.stderr)

    def error(self, text: str) -> None:
        print(f"[错误] {text}", file=sys.stderr)


def print_site_table(ui: Ui, pe: PEFile, states: list[SiteState], value: int) -> None:
    ui.say(f"{'站点':<28}{'文件偏移':<12}{'RVA':<12}{'当前值':<14}{'状态':<12}运行时严格扫描")
    ui.say("-" * 96)
    for s in states:
        if s.match is None:
            ui.say(f"{s.site.name:<28}{'-':<12}{'-':<12}{'-':<14}{STATE_TEXT['missing']:<12}-")
            continue
        rva = pe.rva_of(s.match.file_off)
        rva_text = hexval(rva) if rva is not None else "?"
        runtime_text = "命中" if s.runtime_hits else "认不出(值已改)"
        ui.say(f"{s.site.name:<28}{hexval(s.match.file_off):<12}{rva_text:<12}"
               f"{hexval(s.current):<14}{STATE_TEXT[s.state]:<12}{runtime_text}")
    ui.say(f"\n目标值: {value} ({hexval(value)})   原始值: {ORIGINAL_VALUE} ({hexval(ORIGINAL_VALUE)})")
    ui.say("“运行时严格扫描”= kpatch.dll 按 0x8000 严格匹配时是否还会命中该点位")


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
def read_ini_value(path: str) -> Optional[int]:
    """从 kpatch.ini 里取 [Indices] value（够用就行，不引入 inipp 的完整语义）。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return None
    section = ""
    for line in lines:
        line = line.split(";", 1)[0].split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section != "indices" or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        if key.strip().lower() == "value":
            try:
                return int(raw.strip(), 0)
            except ValueError:
                return None
    return None


def resolve_value(args: argparse.Namespace, target: str, ui: Ui) -> tuple[int, str]:
    if args.value is not None:
        return parse_int(args.value), "命令行 --value"
    candidates = []
    if args.ini:
        candidates.append(args.ini)
    else:
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(target)), "kpatch.ini"))
        candidates.append(os.path.join(os.getcwd(), "kpatch.ini"))
        candidates.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kpatch.ini"))
    for path in candidates:
        if os.path.isfile(path):
            value = read_ini_value(path)
            if value is not None:
                return value, path
    return DEFAULT_VALUE, f"内置默认值（未找到可用的 kpatch.ini）"


# --------------------------------------------------------------------------
# 备份 / 写入
# --------------------------------------------------------------------------
def looks_pristine(pe: PEFile, value: int) -> bool:
    if pe.read_marker() is not None:
        return False
    states = analyze(pe, value)
    if any(s.state == "missing" for s in states):
        return False
    return all(s.state == "original" for s in states)


def make_backup(path: str, original: bytes, explicit: Optional[str], value: int,
                ui: Ui, warnings: list[str]) -> str:
    backup = explicit or (path + ".bak")
    if os.path.exists(backup):
        try:
            with open(backup, "rb") as fh:
                existing = fh.read()
        except OSError as exc:
            raise PatchError(f"无法读取已存在的备份 {backup}: {exc}") from exc
        if existing == original:
            ui.say(f"备份已存在且与当前文件一致，保持不变: {backup}")
            return backup
        try:
            pristine = looks_pristine(PEFile(existing, backup), value)
        except PatchError:
            pristine = False
        if pristine:
            ui.say(f"备份已存在（原始文件），保持不变: {backup}")
            return backup
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = f"{backup}.{stamp}"
        msg = (f"已存在的备份 {explicit or (path + '.bak')} 不是未打补丁的原始文件，"
               f"为避免破坏它，本次备份改写到 {backup}")
        ui.warn(msg)
        warnings.append(msg)
    with open(backup, "wb") as fh:
        fh.write(original)
    ui.say(f"已备份原始文件: {backup}  (sha256 {sha256(original)[:16]}…)")
    return backup


def write_file_atomic(path: str, data: bytes, ui: Ui) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    tmp = os.path.join(directory, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if os.path.exists(path) and not os.access(path, os.W_OK):
            raise PatchError(f"目标文件是只读的，请先去掉只读属性: {path}")
        os.replace(tmp, path)
    except OSError as exc:
        raise PatchError(
            f"写入失败（游戏/Steam 是否还在占用该文件？）: {exc}") from exc
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="static_patch.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="L4D2Fix 静态补丁：直接改写磁盘上的 shaderapidx9.dll，不注入 DLL、不改内存。",
        epilog=(
            "退出码: 0=已打补丁/可以打补丁  1=错误  2=已是补丁状态(未改动)  "
            "3=站点状态异常(未完成)  4=找不到补丁点位\n"
            "示例:\n"
            "  python tools/static_patch.py \"<L4D2>\\bin\\shaderapidx9.dll\" --check\n"
            "  python tools/static_patch.py \"<L4D2>\\bin\\shaderapidx9.dll\" --value 131072\n"
            "  python tools/static_patch.py \"<L4D2>\\bin\\shaderapidx9.dll\" --restore\n"
        ))
    parser.add_argument("dll", nargs="?", help="目标 DLL（通常是 <L4D2>\\bin\\shaderapidx9.dll）")
    parser.add_argument("-n", "--value", metavar="N",
                        help="新的 buffer 大小，十进制或 0x 十六进制；默认读 kpatch.ini 的 [Indices] value")
    parser.add_argument("--ini", metavar="PATH", help="指定 kpatch.ini")
    parser.add_argument("-o", "--output", metavar="PATH",
                        help="写入新文件而不改动原文件（此时不生成备份）")
    parser.add_argument("-c", "--check", "--dry-run", "--status", dest="check", action="store_true",
                        help="只检测并报告，不写任何东西")
    parser.add_argument("--force", action="store_true",
                        help="站点数值与预期不符时也强行写入目标值")
    parser.add_argument("--restore", action="store_true", help="从备份还原原始 DLL")
    parser.add_argument("--backup", metavar="PATH", help="指定备份路径（默认 <dll>.bak）")
    parser.add_argument("--no-backup", action="store_true", help="原地修改但不做备份（不推荐）")
    parser.add_argument("--no-marker", action="store_true", help="不写入补丁标记")
    parser.add_argument("--strip-signature", action="store_true",
                        help="清空嵌入式数字签名目录项（改过字节后签名必然失效）")
    parser.add_argument("--checksum", choices=("auto", "keep", "recompute"), default="auto",
                        help="PE 校验和策略：auto=原来有效则重算（默认）")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    parser.add_argument("--list-patterns", action="store_true", help="打印内置模式表后退出")
    parser.add_argument("-V", "--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    return parser


def do_list_patterns(ui: Ui) -> int:
    ui.say(f"{TOOL_NAME} {TOOL_VERSION} 内置模式表（对应 src/hooks_indices.h）\n")
    for site in SITES:
        pattern = parse_pattern(site.pattern)
        ui.say(f"[{site.index}] {site.name}")
        ui.say(f"    说明     : {site.desc}")
        ui.say(f"    搜索起点 : {'镜像开头' if site.search_from is None else SITES[site.search_from].name}")
        ui.say(f"    写入偏移 : +{site.write_offset}")
        ui.say(f"    通配模式 : {render_pattern(pattern)}")
        ui.say(f"    原版模式 : {render_pattern(pattern, (site.write_offset, ORIGINAL_VALUE))}")
        ui.say("")
    return EXIT_OK


def do_restore(args: argparse.Namespace, ui: Ui, warnings: list[str]) -> int:
    backup = args.backup or (args.dll + ".bak")
    if not os.path.isfile(backup):
        ui.error(f"找不到备份文件: {backup}")
        return EXIT_USAGE
    with open(backup, "rb") as fh:
        data = fh.read()
    try:
        pe = PEFile(data, backup)
    except PatchError as exc:
        ui.error(str(exc))
        return EXIT_USAGE
    value = DEFAULT_VALUE
    if not looks_pristine(pe, value) and not args.force:
        ui.error(f"备份 {backup} 看起来不是“未打补丁的原始文件”，为安全起见不还原。"
                 f"确认无误可加 --force")
        return EXIT_INCOMPLETE
    ui.say(f"从备份还原: {backup} -> {args.dll}")
    ui.say(f"备份 sha256: {sha256(data)[:16]}…")
    if args.check:
        ui.say("（--check：未写入）")
        return EXIT_OK
    write_file_atomic(args.dll, data, ui)
    with open(args.dll, "rb") as fh:
        after = fh.read()
    if after != data:
        ui.error("还原后校验失败：文件内容与备份不一致")
        return EXIT_USAGE
    ui.say("还原完成，已校验一致。")
    return EXIT_OK


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ui = Ui(args.json)
    warnings: list[str] = []
    payload: dict = {"tool": TOOL_NAME, "version": TOOL_VERSION}

    try:
        return _run(args, ui, warnings, payload)
    except PatchError as exc:
        ui.error(str(exc))
        payload["error"] = str(exc)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        return EXIT_USAGE


def _run(args: argparse.Namespace, ui: Ui, warnings: list[str], payload: dict) -> int:
    if args.list_patterns:
        return do_list_patterns(ui)
    if not args.dll:
        raise PatchError("缺少目标 DLL 参数（用 --help 看用法）")
    if args.restore:
        code = do_restore(args, ui, warnings)
        payload["exit_code"] = code
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        return code

    target = os.path.abspath(args.dll)
    if not os.path.isfile(target):
        raise PatchError(f"目标文件不存在: {target}")
    out_path = os.path.abspath(args.output) if args.output else None
    if out_path and os.path.exists(out_path) and not args.check:
        ui.warn(f"输出文件已存在，将被覆盖: {out_path}")

    with open(target, "rb") as fh:
        original = fh.read()
    pe = PEFile(original, target)
    value, value_src = resolve_value(args, target, ui)
    if not 1 <= value <= 0x7FFFFFFF:
        raise PatchError(f"--value 超出可用范围(int32 正数): {value}")

    ui.say(f"{TOOL_NAME} {TOOL_VERSION}")
    ui.say(f"目标文件 : {target}")
    ui.say(f"文件大小 : {len(original)} 字节   sha256 {sha256(original)}")
    ui.say(f"机器类型 : {hexval(pe.machine, 4)} (i386)   节数 {pe.num_sections}   "
           f"SizeOfImage {hexval(pe.size_of_image)}")
    ui.say(f"目标值   : {value} ({hexval(value)})   来源: {value_src}")
    ui.say()

    payload.update({
        "file": target, "size": len(original), "sha256_before": sha256(original),
        "value": value, "value_hex": hexval(value), "value_source": value_src,
        "machine": hexval(pe.machine, 4), "output": out_path,
    })
    if value == ORIGINAL_VALUE:
        ui.say(f"注意：目标值等于原始值 {hexval(ORIGINAL_VALUE)}；"
               f"如果这个文件已经被打过补丁，本次相当于把站点写回原值（还原）。")
        ui.say()

    marker = pe.read_marker()
    if marker:
        ui.say(f"检测到本工具的补丁标记：版本 {marker.version}，写入值 {marker.value} "
               f"({hexval(marker.value)})，站点 {len(marker.offsets)} 个")
        payload["marker"] = {"version": marker.version, "value": marker.value,
                             "offsets": marker.offsets}
        marker_ok = all(pe.read_u32(off) == marker.value for off in marker.offsets)
        if not marker_ok:
            msg = "补丁标记存在，但标记记录的站点数值对不上（文件可能被再次改动过）"
            ui.warn(msg)
            warnings.append(msg)
    else:
        payload["marker"] = None

    if pe.security_dir[0] and pe.security_dir[1]:
        msg = (f"文件带有嵌入式数字签名（目录项 {hexval(pe.security_dir[0])}，{pe.security_dir[1]} 字节）；"
               f"改写字节后签名必然失效，Windows 仍会加载该 DLL，"
               f"需要清掉则加 --strip-signature")
        ui.warn(msg)
        warnings.append(msg)

    states = analyze(pe, value)
    verdict, to_write = decide(states)
    print_site_table(ui, pe, states, value)
    ui.say()

    payload["verdict"] = verdict
    payload["sites"] = [
        {
            "index": s.site.index,
            "name": s.site.name,
            "file_offset": s.match.file_off if s.match else None,
            "rva": pe.rva_of(s.match.file_off) if s.match else None,
            "current": s.current,
            "state": s.state,
            "runtime_strict_hit": s.runtime_hits,
        }
        for s in states
    ]

    if verdict == "not_found":
        ui.error("有站点未找到匹配：这不是受支持的 shaderapidx9.dll 版本"
                 "（游戏更新后需要重新核对模式表，见 tools/static_patch.py 顶部的说明）。")
        code = EXIT_NOT_FOUND
    elif verdict == "patched":
        if marker:
            ui.say(f"该文件已经是补丁状态（标记值 {hexval(marker.value)}），本次不做任何修改。")
        else:
            ui.say("该文件已经是补丁状态（站点数值都等于目标值），本次不做任何修改。")
        if marker and marker.value != value:
            ui.warn(f"注意：文件里的值是 {hexval(marker.value)}，与本次配置的 {hexval(value)} 不同；"
                    f"想改值需要加 --force")
        code = EXIT_ALREADY
    elif verdict == "other" and not args.force:
        odd = ", ".join(f"{s.site.name}={hexval(s.current)}" for s in states if s.state == "other")
        if marker:
            ui.error(f"有站点的当前数值与目标值不同：{odd}；文件里的补丁标记记录的值是 "
                     f"{hexval(marker.value)}。这属于“用另一个值打过补丁”，"
                     f"要按新值重打请加 --force。")
        else:
            ui.error(f"有站点的当前数值既不是 {hexval(ORIGINAL_VALUE)} 也不是目标值：{odd}；"
                     f"无法确认是哪个版本的补丁。已跳过这些站点，确认要覆盖请加 --force。")
        code = EXIT_INCOMPLETE
    else:
        if verdict == "partial":
            ui.warn("该文件此前已被部分修改（部分站点已经是补丁值），本次会把其余站点补齐。")
        code = EXIT_OK

    if args.force and verdict == "other":
        to_write = [s for s in states if s.state != "patched" and s.match is not None]
        code = EXIT_OK

    payload["warnings"] = warnings
    payload["planned_writes"] = [
        {"name": s.site.name, "file_offset": s.match.file_off, "from": s.current, "to": value}
        for s in to_write if s.match
    ]

    if args.check:
        ui.say("--check：未写入任何内容。")
        payload["written"] = False
        payload["exit_code"] = code
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        return code

    if code not in (EXIT_OK,):
        if code != EXIT_ALREADY:
            ui.say("未做任何写入。")
        payload["written"] = False
        payload["exit_code"] = code
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        return code

    if not to_write:
        ui.say("没有需要写入的站点。")
        payload["written"] = False
        payload["exit_code"] = EXIT_ALREADY if verdict == "patched" else code
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        return payload["exit_code"]

    # ---- 真正开始改写 ----
    data = bytearray(original)
    if out_path is None and not args.no_backup:
        make_backup(target, original, args.backup, value, ui, warnings)
        payload["backup"] = args.backup or (target + ".bak")
    elif out_path is None:
        ui.warn("--no-backup：原地修改且没有备份，出问题只能靠 Steam 验证完整性还原。")

    for s in to_write:
        off = s.match.file_off + s.site.write_offset
        data[off:off + 4] = struct.pack("<I", value)
    ui.say(f"已改写 {len(to_write)} 处立即数。")

    if args.strip_signature and pe.security_dir[0] and pe.security_dir[1]:
        data_dir = pe.opt + 96
        entry = data_dir + 8 * IMAGE_DIRECTORY_ENTRY_SECURITY
        data[entry:entry + 8] = b"\0" * 8
        ui.say("已清空嵌入式数字签名目录项。")
        payload["signature_stripped"] = True

    if not args.no_marker:
        patched_pe = PEFile(bytes(data), "patched")
        # 记录“立即数”的偏移，--status 时直接读这几个位置就能核对补丁值
        offsets = [s.match.file_off + s.site.write_offset for s in states if s.match]
        slot = patched_pe.write_marker(value, offsets)
        if slot is None:
            msg = "节表没有空闲表项，跳过写入补丁标记（不影响补丁本身）"
            ui.warn(msg)
            warnings.append(msg)
            payload["marker_written"] = False
        else:
            data = patched_pe.data
            ui.say(f"已写入补丁标记 @ 文件偏移 {hexval(slot)}")
            payload["marker_written"] = True

    # PE 校验和
    new_checksum = None
    if args.checksum == "recompute":
        new_checksum = compute_pe_checksum(bytes(data), pe.checksum_off)
    elif args.checksum == "auto":
        stored = pe.checksum
        if stored != 0 and compute_pe_checksum(original, pe.checksum_off) == stored:
            new_checksum = compute_pe_checksum(bytes(data), pe.checksum_off)
    if new_checksum is not None:
        struct.pack_into("<I", data, pe.checksum_off, new_checksum)
        ui.say(f"已重算 PE 校验和: {hexval(new_checksum)}")
        payload["checksum"] = hexval(new_checksum)
    else:
        payload["checksum"] = hexval(pe.checksum)
        if pe.checksum == 0:
            ui.say("原文件校验和为 0，保持为 0（Windows 对 DLL 不做校验）")

    dest = out_path or target
    write_file_atomic(dest, bytes(data), ui)

    # 写盘后重新读出来校验
    with open(dest, "rb") as fh:
        written = fh.read()
    if out_path is None:
        verify_pe = PEFile(written, dest)
        verify_states = analyze(verify_pe, value)
        bad = [s for s in verify_states if s.state != "patched"]
        ui.say()
        ui.say(f"写入完成: {dest}")
        ui.say(f"写入后 sha256: {sha256(written)}")
        payload["sha256_after"] = sha256(written)
        payload["written"] = True
        if bad:
            ui.error("写入后校验发现站点状态异常: "
                     + ", ".join(f"{s.site.name}={STATE_TEXT[s.state]}" for s in bad))
            payload["exit_code"] = EXIT_INCOMPLETE
            if args.json:
                print(json.dumps(payload, ensure_ascii=False, indent=2))
            return EXIT_INCOMPLETE
        ui.say("写入后校验通过：5 个站点都已是目标值。")
        payload["verified"] = True
    else:
        ui.say()
        ui.say(f"已写出补丁后的文件: {dest}（原文件未改动）")
        ui.say(f"输出文件 sha256: {sha256(written)}")
        payload["sha256_after"] = sha256(written)
        payload["written"] = True

    ui.say()
    ui.say("注意：")
    ui.say("  1) 本脚本为利用 Left4Fix 部分机制实现的 Too Many Indices Error 修复，"
           "本质为 Program Constant Modification 而非 L4D2Fix 的静态版，仅通过"
           "修改 shaderapidx9.dll 中的常数解决 Too Many Indices 问题，没有（也没有被设计实现） Left4Fix 其它功能")
    ui.say("  2) Steam「验证游戏文件完整性」或游戏更新会把这个 DLL 换回原版，届时重新跑一次本脚本；")
    ui.say("  3) 本工具只是把“改内存”换成“改文件”，虽然由于不修改运行时内存 Anti-Cheat 风险更低，"
           "但是并不等于完全 VAC 安全：文件与仓库不一致，虽然由于 VAC 是 Blacklist Sig-matching 而非 Whitelist hash "
           "所以风险较低（这个不大可能被标为外挂），但是**不是**无风险，能不能进 VAC 服请自行判断，作者不为使用该工具导致的 VAC 封禁负责")
    payload["exit_code"] = EXIT_OK
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return EXIT_OK


def cli() -> int:
    # 输出固定 UTF-8：控制台上 Python 本来就按 Unicode 写，重定向到文件/管道时也不会变乱码
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass
    try:
        return main()
    except KeyboardInterrupt:
        return 130
    except PatchError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(cli())
