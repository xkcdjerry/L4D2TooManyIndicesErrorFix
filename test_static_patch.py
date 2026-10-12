#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/static_patch.py 的回归测试。

测试样本用真实的 32 位系统 DLL（SysWOW64）改造而成：在 .text 里按
hooks_indices.h 的顺序塞进 5 个补丁点位，然后：
  * 和“kpatch.dll 的运行时扫描算法”（测试里独立实现一遍）对拍，确认位置一致；
  * 覆盖 未打补丁 / 已打补丁 / 部分打补丁 / 数值异常 / 找不到点位 五种状态；
  * 确认报告而不是静默覆盖、备份/还原、以及 --force 重打的语义。

运行: python tools/test_static_patch.py -v
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import unittest
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import static_patch as sp  # noqa: E402

SCRIPT = os.path.join(HERE, "static_patch.py")
PY = sys.executable
# 测试用的临时目录放在仓库里（沙箱/受限环境下系统临时目录不一定可写）
TMP_ROOT = os.environ.get("L4D2FIX_TEST_TMP") or os.path.join(os.path.dirname(HERE), ".test-tmp")

BASE_CANDIDATES = [
    r"C:\Windows\SysWOW64\version.dll",
    r"C:\Windows\SysWOW64\netutils.dll",
    r"C:\Windows\SysWOW64\cryptbase.dll",
    r"C:\Windows\SysWOW64\profapi.dll",
    r"C:\Windows\SysWOW64\wtsapi32.dll",
    r"C:\Windows\SysWOW64\kernel.appcore.dll",
    r"C:\Windows\SysWOW64\mswsock.dll",
    r"C:\Windows\SysWOW64\d3d9.dll",
]

FILLER = 0x90
STRIDE = 0x40          # 站点间距
TEXT_INJECT_OFF = 0x100  # 注入点到 .text 节原始数据起点的距离

_base_cache = None


def site_bytes(site, value):
    """按站点模式生成一段字节；立即数位置填 value，其余通配字节填固定值。"""
    pattern = sp.parse_pattern(site.pattern)
    out = bytearray()
    for i, byte in enumerate(pattern):
        if byte is None:
            if site.write_offset <= i < site.write_offset + 4:
                byte = (value >> (8 * (i - site.write_offset))) & 0xFF
            else:
                byte = 0x10 + i
        out.append(byte)
    return bytes(out)


def build_blob(value):
    """生成 5 个站点连成的字节块，返回 (blob, 相对 blob 起点的立即数偏移列表)。"""
    blob = bytearray()
    rel = []
    for site in sp.SITES:
        assert len(blob) % STRIDE == 0
        body = site_bytes(site, value)
        rel.append(len(blob) + site.write_offset)
        blob += body
        blob += bytes([FILLER]) * (STRIDE - len(body))
    return bytes(blob), rel


def pick_text_section(pe):
    execs = [s for s in pe.sections if s.executable and s.raw_size >= 0x2000 and s.raw_ptr]
    return max(execs, key=lambda s: s.raw_size)


def make_fixture(base, value=sp.ORIGINAL_VALUE):
    """在 base 的 .text 里注入 5 个点位，返回 (bytes, 5 个立即数的文件偏移)。"""
    with open(base, "rb") as fh:
        data = bytearray(fh.read())
    pe = sp.PEFile(bytes(data), base)
    text = pick_text_section(pe)
    at = text.raw_ptr + TEXT_INJECT_OFF
    blob, rel = build_blob(value)
    if at + len(blob) > text.raw_ptr + text.raw_size:
        raise AssertionError("注入点越界")
    data[at:at + len(blob)] = blob
    return bytes(data), [at + r for r in rel]


def chain_offsets(data, strict):
    pe = sp.PEFile(data, "fixture")
    return [None if m is None else m.file_off for m in sp.resolve_chain(pe, strict)]


def match_starts(imm_offsets):
    """把“立即数的文件偏移”换算成“模式匹配起点”，方便和扫描结果对拍。"""
    return [off - site.write_offset for off, site in zip(imm_offsets, sp.SITES)]


def runtime_scan_reference(data):
    """独立复刻 src/hooks_indices.h::PatchIndices() 的严格扫描（立即数必须 0x8000）。

    故意不复用 static_patch 的实现：用来给静态补丁的位置对拍。
    """
    image = data
    results = []
    for site in sp.SITES:
        if site.index == 0:
            start = 0
        elif site.index == 4:
            start = results[2]
        else:
            start = results[site.index - 1]
        if start is None:
            results.append(None)
            continue
        pattern = [None if t == "??" else int(t, 16) for t in site.pattern.split()]
        # 严格模式：立即数位置固定为 0x8000
        for k in range(4):
            pattern[site.write_offset + k] = (sp.ORIGINAL_VALUE >> (8 * k)) & 0xFF
        found = None
        for i in range(start, len(image) - len(pattern) + 1):
            if all(b is None or image[i + j] == b for j, b in enumerate(pattern)):
                found = i
                break
        results.append(found)
    return results


def get_base():
    global _base_cache
    if _base_cache:
        return _base_cache
    for base in BASE_CANDIDATES:
        if not os.path.isfile(base):
            continue
        try:
            data, expected = make_fixture(base)
        except Exception:
            continue
        loose = chain_offsets(data, strict=False)
        strict = chain_offsets(data, strict=True)
        want = match_starts(expected)
        if loose == want and strict == want:
            _base_cache = base
            return base
    raise unittest.SkipTest("找不到合适的 32 位系统 DLL 作为测试样本")


def make_temp_fixture(tmp, name="shaderapidx9.dll", value=sp.ORIGINAL_VALUE):
    data, expected = make_fixture(get_base(), value)
    path = os.path.join(tmp, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path, data, expected


def run_cli(*args, cwd=None):
    proc = subprocess.run([PY, SCRIPT, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", cwd=cwd)
    return proc.returncode, proc.stdout, proc.stderr


def read(path):
    with open(path, "rb") as fh:
        return fh.read()


def make_case_dir():
    """建一个临时用例目录。

    不用 tempfile.mkdtemp：它会给出一个“仅所有者可访问”的收紧 ACL，
    在受限/沙箱环境里连自己都写不进去；os.makedirs 的目录会继承父目录权限。
    """
    os.makedirs(TMP_ROOT, exist_ok=True)
    path = os.path.join(TMP_ROOT, "case-" + uuid.uuid4().hex[:10])
    os.makedirs(path, exist_ok=True)
    return path


def tearDownModule():
    """用例目录清空后把 .test-tmp 也删掉，别在仓库里留垃圾。"""
    try:
        if os.path.isdir(TMP_ROOT) and not os.listdir(TMP_ROOT):
            os.rmdir(TMP_ROOT)
    except OSError:
        pass


class FixtureSanityTest(unittest.TestCase):
    def test_chain_matches_runtime_scan_algorithm(self):
        """静态补丁用的顺序链必须和 kpatch.dll 的运行时扫描结果完全一致。"""
        for base in BASE_CANDIDATES:
            if not os.path.isfile(base):
                continue
            data, expected = make_fixture(base)
            want = match_starts(expected)
            self.assertEqual(runtime_scan_reference(data), want,
                             f"{base}: 与运行时扫描算法不一致")
            self.assertEqual(chain_offsets(data, strict=True), want)
            self.assertEqual(chain_offsets(data, strict=False), want)

    def test_checksum_algorithm_matches_real_dlls(self):
        """PE 校验和算法要用真实 DLL 自带的校验和验证。"""
        checked = 0
        for base in BASE_CANDIDATES:
            if not os.path.isfile(base):
                continue
            data = read(base)
            pe = sp.PEFile(data, base)
            if pe.checksum == 0:
                continue
            self.assertEqual(sp.compute_pe_checksum(data, pe.checksum_off), pe.checksum,
                             f"{base}: 校验和算法不对")
            checked += 1
        if not checked:
            self.skipTest("候选 DLL 都没有自带校验和")


class StaticPatchCliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = make_case_dir()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.dll, self.original, self.offsets = make_temp_fixture(self.tmp)

    # -- 基本流程 ---------------------------------------------------------
    def test_check_reports_unpatched_and_writes_nothing(self):
        code, out, err = run_cli(self.dll, "--check", "-n", str(sp.DEFAULT_VALUE))
        self.assertEqual(code, 0, f"stdout={out}\nstderr={err}")
        self.assertIn("未打补丁", out)
        self.assertEqual(read(self.dll), self.original, "--check 不应该改动文件")
        self.assertFalse(os.path.exists(self.dll + ".bak"), "--check 不应该建备份")

    def test_patch_then_second_run_reports_already_patched(self):
        code, out, err = run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE))
        self.assertEqual(code, 0, f"stdout={out}\nstderr={err}")
        patched = read(self.dll)
        for off in self.offsets:
            self.assertEqual(patched[off:off + 4], struct.pack("<I", sp.DEFAULT_VALUE))
        marker = sp.PEFile(patched, self.dll).read_marker()
        self.assertIsNotNone(marker, "应该写入补丁标记")
        self.assertEqual(marker.value, sp.DEFAULT_VALUE)
        self.assertEqual(sorted(marker.offsets), sorted(self.offsets))

        # 第二次运行：必须报告“已经是补丁状态”，且一个字节都不改
        code2, out2, _ = run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE))
        self.assertEqual(code2, sp.EXIT_ALREADY, f"stdout={out2}")
        self.assertIn("已经是补丁状态", out2)
        self.assertEqual(read(self.dll), patched, "第二次运行不应该改动文件")

    def test_patch_diff_is_minimal(self):
        run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE))
        patched = read(self.dll)
        self.assertEqual(len(patched), len(self.original), "文件大小不能变")
        marker = sp.PEFile(patched, self.dll).read_marker()
        allowed = set()
        for off in self.offsets:
            allowed.update(range(off, off + 4))
        allowed.update(range(marker.slot_off, marker.slot_off + 40))
        pe = sp.PEFile(self.original, self.dll)
        allowed.update(range(pe.checksum_off, pe.checksum_off + 4))
        diff = {i for i in range(len(patched)) if patched[i] != self.original[i]}
        self.assertTrue(diff, "应该确实改了东西")
        self.assertLessEqual(diff, allowed, f"改动了预期之外的字节: {sorted(diff - allowed)[:16]}")

    def test_backup_then_restore(self):
        code, out, err = run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE))
        self.assertEqual(code, 0, f"stdout={out}\nstderr={err}")
        self.assertTrue(os.path.exists(self.dll + ".bak"))
        self.assertEqual(read(self.dll + ".bak"), self.original)

        code, out, err = run_cli(self.dll, "--restore")
        self.assertEqual(code, 0, f"stdout={out}\nstderr={err}")
        self.assertEqual(read(self.dll), self.original, "还原后应该与原文件一致")

    def test_already_patched_without_marker(self):
        """没有标记时也要靠立即数认出来，仍然报告而不是覆盖。"""
        code, _, err = run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE), "--no-marker")
        self.assertEqual(code, 0, err)
        patched = read(self.dll)
        self.assertIsNone(sp.PEFile(patched, self.dll).read_marker())
        code2, out2, _ = run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE))
        self.assertEqual(code2, sp.EXIT_ALREADY, f"stdout={out2}")
        self.assertIn("已经是补丁状态", out2)
        self.assertEqual(read(self.dll), patched)

    def test_value_equal_to_original_is_noop_for_pristine_file(self):
        code, out, _ = run_cli(self.dll, "-n", str(sp.ORIGINAL_VALUE))
        self.assertEqual(code, sp.EXIT_ALREADY, f"stdout={out}")
        self.assertEqual(read(self.dll), self.original)

    # -- 异常状态 ---------------------------------------------------------
    def test_partial_patch_is_completed_and_reported(self):
        data = bytearray(self.original)
        data[self.offsets[0]:self.offsets[0] + 4] = struct.pack("<I", sp.DEFAULT_VALUE)
        with open(self.dll, "wb") as fh:
            fh.write(data)
        code, out, err = run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE))
        self.assertEqual(code, 0, f"stdout={out}\nstderr={err}")
        self.assertIn("已被部分修改", out + err)
        patched = read(self.dll)
        for off in self.offsets:
            self.assertEqual(patched[off:off + 4], struct.pack("<I", sp.DEFAULT_VALUE))

    def test_other_value_is_refused_without_force(self):
        data = bytearray(self.original)
        data[self.offsets[2]:self.offsets[2] + 4] = struct.pack("<I", 0xDEADBEEF)
        with open(self.dll, "wb") as fh:
            fh.write(data)
        code, out, err = run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE))
        self.assertEqual(code, sp.EXIT_INCOMPLETE, f"stdout={out}\nstderr={err}")
        self.assertIn("--force", err)
        self.assertEqual(read(self.dll), bytes(data), "拒绝时不能写入")

        code, out, err = run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE), "--force")
        self.assertEqual(code, 0, f"stdout={out}\nstderr={err}")
        patched = read(self.dll)
        for off in self.offsets:
            self.assertEqual(patched[off:off + 4], struct.pack("<I", sp.DEFAULT_VALUE))

    def test_repatch_with_new_value_needs_force(self):
        run_cli(self.dll, "-n", "131072")
        code, out, err = run_cli(self.dll, "-n", "65536")
        self.assertEqual(code, sp.EXIT_INCOMPLETE, f"stdout={out}\nstderr={err}")
        self.assertIn("force", err.lower() + out.lower())
        self.assertEqual(read(self.dll)[self.offsets[0]:self.offsets[0] + 4],
                         struct.pack("<I", 131072), "拒绝时不能写入")

        code, out, err = run_cli(self.dll, "-n", "65536", "--force")
        self.assertEqual(code, 0, f"stdout={out}\nstderr={err}")
        patched = read(self.dll)
        for off in self.offsets:
            self.assertEqual(patched[off:off + 4], struct.pack("<I", 65536))
        self.assertEqual(sp.PEFile(patched, self.dll).read_marker().value, 65536)

    def test_missing_pattern_reports_not_found(self):
        data = bytearray(self.original)
        data[self.offsets[4] - sp.SITES[4].write_offset:self.offsets[4] - sp.SITES[4].write_offset + 17] = b"\xCC" * 17
        with open(self.dll, "wb") as fh:
            fh.write(data)
        code, out, err = run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE))
        self.assertEqual(code, sp.EXIT_NOT_FOUND, f"stdout={out}\nstderr={err}")
        self.assertEqual(read(self.dll), bytes(data))

    def test_rejects_64bit_dll(self):
        x64 = r"C:\Windows\System32\version.dll"
        if not os.path.isfile(x64):
            self.skipTest("找不到 64 位样本")
        dst = os.path.join(self.tmp, "x64.dll")
        shutil.copyfile(x64, dst)
        code, out, err = run_cli(dst, "-n", str(sp.DEFAULT_VALUE))
        self.assertEqual(code, sp.EXIT_USAGE, f"stdout={out}\nstderr={err}")
        self.assertIn("64 位", err)

    def test_not_a_pe_file(self):
        dst = os.path.join(self.tmp, "not_a_dll.txt")
        with open(dst, "w") as fh:
            fh.write("hello")
        code, _, err = run_cli(dst)
        self.assertEqual(code, sp.EXIT_USAGE)
        self.assertIn("PE", err)

    # -- 其它开关 ---------------------------------------------------------
    def test_output_mode_leaves_input_untouched(self):
        out_path = os.path.join(self.tmp, "patched.dll")
        code, out, err = run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE), "-o", out_path)
        self.assertEqual(code, 0, f"stdout={out}\nstderr={err}")
        self.assertEqual(read(self.dll), self.original, "输出模式不应该改动原文件")
        self.assertFalse(os.path.exists(self.dll + ".bak"))
        patched = read(out_path)
        for off in self.offsets:
            self.assertEqual(patched[off:off + 4], struct.pack("<I", sp.DEFAULT_VALUE))

    def test_json_output(self):
        code, out, err = run_cli(self.dll, "--check", "-n", str(sp.DEFAULT_VALUE), "--json")
        self.assertEqual(code, 0, f"stderr={err}")
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "unpatched")
        self.assertEqual(payload["value"], sp.DEFAULT_VALUE)
        self.assertEqual(len(payload["sites"]), 5)
        self.assertTrue(all(s["runtime_strict_hit"] for s in payload["sites"]))

    def test_strip_signature(self):
        data = bytearray(self.original)
        pe = sp.PEFile(bytes(data), self.dll)
        entry = pe.opt + 96 + 8 * sp.IMAGE_DIRECTORY_ENTRY_SECURITY
        if pe.security_dir == (0, 0):
            struct.pack_into("<II", data, entry, 0x1000, 0x100)
            with open(self.dll, "wb") as fh:
                fh.write(data)
        code, out, err = run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE))
        self.assertEqual(code, 0, f"stdout={out}\nstderr={err}")
        self.assertIn("数字签名", err + out)
        code, out, err = run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE + 4), "--strip-signature", "--force")
        self.assertEqual(code, 0, f"stdout={out}\nstderr={err}")
        patched = read(self.dll)
        self.assertEqual(patched[entry:entry + 8], b"\0" * 8)

    def test_value_from_ini_next_to_dll(self):
        with open(os.path.join(self.tmp, "kpatch.ini"), "w", encoding="utf-8") as fh:
            fh.write("[System]\ndebug = false\n\n[Indices]\nenable = true\nvalue = 196608\n")
        code, out, err = run_cli(self.dll, "--check", cwd=self.tmp)
        self.assertEqual(code, 0, f"stdout={out}\nstderr={err}")
        self.assertIn("196608", out)
        self.assertIn("kpatch.ini", out)

    def test_payload_mode_exit_codes_are_stable(self):
        """--check 的退出码要和真正执行时的退出码一致。"""
        code, _, _ = run_cli(self.dll, "--check", "-n", str(sp.DEFAULT_VALUE))
        self.assertEqual(code, 0)
        run_cli(self.dll, "-n", str(sp.DEFAULT_VALUE))
        code, _, _ = run_cli(self.dll, "--check", "-n", str(sp.DEFAULT_VALUE))
        self.assertEqual(code, sp.EXIT_ALREADY)


if __name__ == "__main__":
    unittest.main(verbosity=2)
